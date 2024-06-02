///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/Support/MemUtils.h>
#include <s2e/Plugins/OSMonitors/Support/MemoryMap.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/Plugins/Searchers/SeedSearcher.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>

#include <klee/Solver.h>
#include <klee/util/ExprTemplates.h>

#include <iostream>

#include "DecreeMonitor.h"

using namespace klee;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(DecreeMonitor, "DecreeMonitor S2E plugin", "", "BaseInstructions", "LinuxMonitor", "Vmi");

namespace decree {

// From arch/x86/include/asm/page_types.h
static const unsigned PAGE_SHIFT = 12;
static const unsigned PAGE_SIZE = 1UL << PAGE_SHIFT;

// From arch/x86/include/asm/page_32_types.h
static const unsigned THREAD_SIZE_ORDER = 1;

// From arch/x86/include/asm/page_32_types.h
static const unsigned THREAD_SIZE = PAGE_SIZE << THREAD_SIZE_ORDER;

///
/// Pointer to the address of ESP0 in the Task State Segment (TSS).
/// ESP0 is the stack pointer to load when in kernel mode
///
static const unsigned TSS_ESP0_OFFSET = 4;

/// \brief We assume allocation of this amount of memory will never fail
static const unsigned SAFE_ALLOCATE_SIZE = 16 * 1024 * 1024;

} // namespace decree

void DecreeMonitor::initialize() {
    m_base = s2e()->getPlugin<BaseInstructions>();

    m_vmi = s2e()->getPlugin<Vmi>();

    // XXX: this is a circular dependency, will require further refactoring
    m_memutils = s2e()->getPlugin<MemUtils>();
    if (!m_memutils) {
        getWarningsStream() << "Requires MemUtils\n";
        exit(-1);
    }

    // XXX: this is a circular dependency, will require further refactoring
    m_map = s2e()->getPlugin<MemoryMap>();
    if (!m_map) {
        getWarningsStream() << "Requires MemoryMap\n";
        exit(-1);
    }

    m_seedSearcher = s2e()->getPlugin<seeds::SeedSearcher>();

    m_detector = s2e()->getPlugin<ProcessExecutionDetector>();

    m_monitor = s2e()->getPlugin<LinuxMonitor>();

    ConfigFile *cfg = s2e()->getConfig();

    m_symbolicReadLimitCount = cfg->getInt(getConfigKey() + ".symbolicReadLimitCount", 16 * 1024 * 1024);
    m_maxReadLimitCount = cfg->getInt(getConfigKey() + ".maxReadLimitCount", 16 * 1024 * 1024);
    if (!(m_symbolicReadLimitCount <= m_maxReadLimitCount)) {
        getWarningsStream() << "symbolicReadLimitCount must be smaller than maxReadLimitCount\n";
        exit(-1);
    }

    m_invokeOriginalSyscalls = cfg->getBool(getConfigKey() + ".invokeOriginalSyscalls", false);
    m_printOpcodeOffsets = cfg->getBool(getConfigKey() + ".printOpcodeOffsets", false);
    m_concolicMode = cfg->getBool(getConfigKey() + ".concolicMode", false);
    m_logWrittenData = cfg->getBool(getConfigKey() + ".logWrittenData", true);
    m_handleSymbolicAllocateSize = cfg->getBool(getConfigKey() + ".handleSymbolicAllocateSize", false);
    m_handleSymbolicBufferSize = cfg->getBool(getConfigKey() + ".handleSymbolicBufferSize", false);
    m_feedConcreteData = cfg->getString(getConfigKey() + ".feedConcreteData", "");

    m_symbolicReadLimitCount += m_feedConcreteData.length();
    m_maxReadLimitCount += m_feedConcreteData.length();

    m_firstSegfault = true;
    m_timeToFirstSegfault = -1;
    time(&m_startTime);

    m_monitor->onSegFault.connect(sigc::mem_fun(*this, &DecreeMonitor::onSegFault));
}

class DecreeMonitorState : public PluginState {
public:
    /* How many bytes (symbolic or concrete) were read by each pid */
    std::map<uint64_t /* pid */, uint64_t> m_readBytesCount;

    /* Sum of all the values in m_readBytesCount */
    unsigned m_totalReadBytesCount;

    std::vector<uint8_t> m_concreteData;
    bool m_invokeOriginalSyscalls;
    bool m_concolicMode;

    virtual DecreeMonitorState *clone() const {
        DecreeMonitorState *ret = new DecreeMonitorState(*this);
        /**
         * Can't use the original pov on alternate paths, because it
         * is out of sync.
         */
        ret->m_invokeOriginalSyscalls = false;
        ret->m_concolicMode = false;
        return ret;
    }

    DecreeMonitorState(bool invokeOriginalSyscalls, bool concolicMode) {
        m_invokeOriginalSyscalls = invokeOriginalSyscalls;
        m_concolicMode = concolicMode;
        m_totalReadBytesCount = 0;
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        DecreeMonitor *plugin = static_cast<DecreeMonitor *>(p);
        return new DecreeMonitorState(plugin->m_invokeOriginalSyscalls, plugin->m_concolicMode);
    }
};

unsigned DecreeMonitor::getSymbolicReadsCount(S2EExecutionState *state) const {
    DECLARE_PLUGINSTATE_CONST(DecreeMonitorState, state);
    return plgState->m_totalReadBytesCount;
}

void DecreeMonitor::getPreFeedData(S2EExecutionState *state, uint64_t pid, uint64_t count, std::vector<uint8_t> &data) {
    // TODO: fix POV generation - it does not use these concrete values

    DECLARE_PLUGINSTATE(DecreeMonitorState, state);

    s2e_assert(state, plgState->m_readBytesCount[pid] <= UINT64_MAX - count, "Read count overflow");
    s2e_assert(state, plgState->m_readBytesCount[pid] + count <= m_feedConcreteData.length(), "Invalid count");

    std::vector<uint8_t> buffer;
    for (unsigned i = 0; i < count; ++i) {
        uint8_t value = m_feedConcreteData[plgState->m_readBytesCount[pid] + i];
        data.push_back(value);
    }
}

void DecreeMonitor::getRandomData(S2EExecutionState *state, uint64_t count, std::vector<uint8_t> &data) {
    for (unsigned i = 0; i < count; ++i) {
        uint8_t value = rand();
        data.push_back(value);
    }
}

ref<Expr> DecreeMonitor::makeSymbolicRead(S2EExecutionState *state, uint64_t pid, uint64_t fd, uint64_t buf,
                                          uint64_t count, ref<Expr> countExpr) {
    DECLARE_PLUGINSTATE(DecreeMonitorState, state);

    if (plgState->m_readBytesCount[pid] < m_feedConcreteData.length()) {
        uint64_t feedCount = std::min(count, m_feedConcreteData.length() - plgState->m_readBytesCount[pid]);

        std::vector<uint8_t> data;
        getPreFeedData(state, pid, feedCount, data);

        bool ok = state->mem()->write(buf, &data[0], feedCount);
        s2e_assert(state, ok, "Failed to write memory");

        plgState->m_readBytesCount[pid] += feedCount;
        plgState->m_totalReadBytesCount += feedCount;
        onConcreteRead.emit(state, pid, fd, data);
        return E_CONST(feedCount, Expr::Int32);
    }

    if (plgState->m_readBytesCount[pid] < m_symbolicReadLimitCount) {
        uint64_t feedCount = std::min(count, m_symbolicReadLimitCount - plgState->m_readBytesCount[pid]);
        ref<Expr> feedCountExpr = E_MIN(
            countExpr, E_CONST(m_symbolicReadLimitCount - plgState->m_readBytesCount[pid], countExpr->getWidth()));

        std::vector<std::pair<std::vector<klee::ref<klee::Expr>>, std::string>> data;
        for (unsigned i = 0; i < feedCount; i++) {
            std::vector<ref<Expr>> varData;
            std::string varName;
            m_base->makeSymbolic(state, buf + i, 1, "receive", &varData, &varName);
            data.push_back(std::make_pair(varData, varName));
        }

        plgState->m_readBytesCount[pid] += feedCount;
        plgState->m_totalReadBytesCount += feedCount;
        onSymbolicRead.emit(state, pid, fd, feedCount, data, feedCountExpr);
        return feedCountExpr;
    }

    if (plgState->m_readBytesCount[pid] < m_maxReadLimitCount) {
        /**
         * Note: using random data may lead to non-replayable POVs (mostly cookies)
         * This is meant to prevent path explosion in the simplest checker configuration.
         */

        static bool printed_warning = false;
        if (!printed_warning) {
            printed_warning = true;
            getDebugStream(state) << "Symbolic read threshold exceeded, using random data\n";
        }

        uint64_t feedCount = std::min(count, m_maxReadLimitCount - plgState->m_readBytesCount[pid]);

        std::vector<uint8_t> data;
        getRandomData(state, feedCount, data);

        bool ok = state->mem()->write(buf, &data[0], feedCount);
        s2e_assert(state, ok, "Failed to write memory");

        plgState->m_readBytesCount[pid] += feedCount;
        plgState->m_totalReadBytesCount += feedCount;
        onConcreteRead.emit(state, pid, fd, data);
        return E_CONST(feedCount, Expr::Int32);
    }

    g_s2e->getExecutor()->terminateState(*state, "read data limit exceeded");
    return E_CONST(0, Expr::Int32);
}

void DecreeMonitor::handleReadData(S2EExecutionState *state, uint64_t pid, const S2E_DECREEMON_COMMAND_READ_DATA &d) {
    if (!isReadFd(d.fd)) {
        return;
    }

    bool isSeedState = m_seedSearcher ? m_seedSearcher->isSeedState(state) : false;

    ref<Expr> countExpr;
    if (m_handleSymbolicBufferSize && !isSeedState) {
        countExpr = state->mem()->read(d.size_expr_addr, state->getPointerWidth());
        s2e_assert(state, countExpr, "Failed to read memory");
    } else {
        countExpr = E_CONST(d.buffer_size, Expr::Int32);
    }

    ref<Expr> bytesSentExpr = makeSymbolicRead(state, pid, d.fd, d.buffer, d.buffer_size, countExpr);

    if (isa<ConstantExpr>(bytesSentExpr)) {
        bool ok = state->writePointer(d.result_addr, dyn_cast<ConstantExpr>(bytesSentExpr)->getZExtValue());
        s2e_assert(state, ok, "Failed to write memory");
    } else {
        bool ok = state->mem()->write(d.result_addr, bytesSentExpr);
        s2e_assert(state, ok, "Failed to write memory");
    }

    DECLARE_PLUGINSTATE(DecreeMonitorState, state);
    getDebugStream(state) << "handleReadData: readCount=" << plgState->m_readBytesCount[pid] << "\n";
}

void DecreeMonitor::handleReadDataPost(S2EExecutionState *state, uint64_t pid,
                                       const S2E_DECREEMON_COMMAND_READ_DATA_POST &d) {
    if (!isReadFd(d.fd)) {
        return;
    }

    DECLARE_PLUGINSTATE(DecreeMonitorState, state);

    if (plgState->m_concolicMode) {
        std::vector<std::pair<std::vector<klee::ref<klee::Expr>>, std::string>> data;

        for (unsigned i = 0; i < d.buffer_size; i++) {
            std::vector<ref<Expr>> varData;
            std::string varName;

            m_base->makeSymbolic(state, d.buffer + i, 1, "receive", &varData, &varName);
            data.push_back(std::make_pair(varData, varName));
        }

        plgState->m_readBytesCount[pid] += d.buffer_size;
        plgState->m_totalReadBytesCount += d.buffer_size;
        onSymbolicRead.emit(state, pid, d.fd, d.buffer_size, data, ConstantExpr::create(d.buffer_size, Expr::Int32));

        getDebugStream(state) << "handleReadData: readCount=" << plgState->m_readBytesCount[pid] << "\n";
    }
}

void DecreeMonitor::handleWriteData(S2EExecutionState *state, uint64_t pid, const S2E_DECREEMON_COMMAND_WRITE_DATA &d) {
    if (!isWriteFd(d.fd)) {
        return;
    }

    uint64_t actualCount; // how many bytes were written to output by kernel
    bool ok = state->readPointer(d.buffer_size_addr, actualCount);
    s2e_assert(state, ok, "Failed to read memory");

    ref<Expr> countExpr = state->mem()->read(d.size_expr_addr, state->getPointerWidth());
    s2e_assert(state, countExpr, "Failed to read memory");
    countExpr = E_MIN(countExpr, E_CONST(actualCount, state->getPointerWidth()));

    std::stringstream ss;

    std::vector<klee::ref<klee::Expr>> vec;
    for (unsigned i = 0; i < actualCount; ++i) {
        klee::ref<klee::Expr> e = m_memutils->read(state, d.buffer + i);
        s2e_assert(state, e, "Failed to read memory byte of pid " << hexval(pid) << " at " << hexval(d.buffer + i));

        vec.push_back(e);

        if (m_logWrittenData) {
            if (isa<klee::ConstantExpr>(e)) {
                klee::ref<klee::ConstantExpr> ce = dyn_cast<klee::ConstantExpr>(e);
                ss << charval(ce->getZExtValue());
            } else {
                ss << e << " ";
            }
        }
    }

    if (m_logWrittenData) {
        getDebugStream(state) << "handleWriteData pid=" << hexval(pid) << " fd=" << d.fd << ": " << ss.str() << "\n";
    }

    bool isSeedState = m_seedSearcher ? m_seedSearcher->isSeedState(state) : false;
    if (m_handleSymbolicBufferSize && !isSeedState && !isa<ConstantExpr>(countExpr)) {
        bool ok = state->mem()->write(d.buffer_size_addr, countExpr);
        s2e_assert(state, ok, "Failed to write memory");
    }

    onWrite.emit(state, pid, d.fd, vec, countExpr);
}

void DecreeMonitor::handleFdWait(S2EExecutionState *state, S2E_DECREEMON_COMMAND &d, uintptr_t addr) {
    DECLARE_PLUGINSTATE(DecreeMonitorState, state);

    d.FDWait.invoke_orig = 0;
    if (plgState->m_invokeOriginalSyscalls) {
        d.FDWait.invoke_orig = 1;
    }

    if (d.FDWait.has_timeout) {
        using namespace klee;
        // Switch to symbolic mode
        state->jumpToSymbolicCpp();

        getDebugStream(state) << "fdwait timeout: " << d.FDWait.tv_sec << " " << d.FDWait.tv_nsec << "\n";

        // Create a symbolic timeout variable
        uint8_t val = 0;
        ref<Expr> timeout = state->createSymbolicValue("timeout", val);

        // Build expression: if timeout == 0 then 0 else nfds
        ref<Expr> result = E_ITE(E_EQ(timeout, E_CONST(0, Expr::Int8)), //
                                 E_CONST(0, Expr::Int64), E_CONST(d.FDWait.nfds, Expr::Int64));

        // Need to write it back, the kernel reads 'invoke_orig'
        bool ok = state->mem()->write(addr, &d, sizeof(d));
        s2e_assert(state, ok, "Failed to write memory");

        uintptr_t resultAddress = addr + offsetof(S2E_DECREEMON_COMMAND, FDWait.result);
        ok = state->mem()->write(resultAddress, result);
        s2e_assert(state, ok, "Failed to write memory");

        /*state->regs()->write<target_ulong>(CPU_OFFSET(eip), state->regs()->getPc() + 10);

        Executor::StatePair sp = s2e()->getExecutor()->fork(*state, condition, false);
        s2e()->getExecutor()->notifyFork(*state, condition, sp);

        throw CpuExitException();*/

    } else {
        d.FDWait.result = d.FDWait.nfds;
        bool ok = state->mem()->write(addr, &d, sizeof(d));
        s2e_assert(state, ok, "Failed to write memory");
    }
}

void DecreeMonitor::handleRandom(S2EExecutionState *state, uint64_t pid, const S2E_DECREEMON_COMMAND_RANDOM &d) {
    // Always make this concolic, POV generator needs as many real concrete
    // values as possible.
    std::vector<klee::ref<klee::Expr>> data;

    // It is important to create one variable for each random byte.
    // The DecreePovGenerator will assume one byte var == one byte nonce.
    for (uint64_t i = 0; i < d.buffer_size; ++i) {
        std::vector<klee::ref<klee::Expr>> sd;
        m_base->makeSymbolic(state, d.buffer + i, 1, "random", &sd);
        s2e_assert(nullptr, sd.size() == 1, "makesymbolic returned wrong number of bytes");
        data.push_back(sd[0]);
    }

    onRandom.emit(state, pid, data);
}

void DecreeMonitor::handleGetCfgBool(S2EExecutionState *state, uint64_t pid, S2E_DECREEMON_COMMAND_GET_CFG_BOOL &d) {
    std::string key;
    bool ok = state->mem()->readString(d.key_addr, key, 256);
    s2e_assert(state, ok, "Failed to read memory");

    bool value;
    if (key == "invokeOriginalSyscalls") {
        DECLARE_PLUGINSTATE(DecreeMonitorState, state);

        // We always want to invoke original syscalls when not in cb process
        // (e.g., when in seed process, which are also decree binaries).
        // XXX: this induces  a circular dependency between DecreeMonitor and
        // ProcessExecutionDetector. Better design would be to have a signal
        // to ask other plugins whether this process should be instrumented or not.
        if (m_detector && !m_detector->isTrackedPid(state, pid)) {
            value = true;
        } else {
            value = plgState->m_invokeOriginalSyscalls;
        }
    } else {
        s2e_assert(state, false, "Unknown config key name: " << key);
    }

    d.value = value;
}

///
/// \brief Get the base address of the \c task_struct in the kernel
///
/// Note that the method used (i.e. reading the TSS to get the \c current_thread_info, as described at
/// https://stackoverflow.com/questions/11961490/understanding-the-getting-of-task-struct-pointer-from-process-kernel-stack)
/// is only appicable for Linux kernel < 4.x. The Linux kernel used for the CGC is version 3.x
///
target_ulong DecreeMonitor::getTaskStructPtr(S2EExecutionState *state) {
    target_ulong esp0;
    target_ulong esp0Addr = env->tr.base + decree::TSS_ESP0_OFFSET;

    if (!state->mem()->read(esp0Addr, &esp0, sizeof(esp0))) {
        return -1;
    }

    // Based on the "current_stack" function in arch/x86/kernel/irq_32.c
    target_ulong currentThreadInfo = esp0 & ~(decree::THREAD_SIZE - 1);
    target_ulong taskStructPtr;

    if (!state->mem()->read(currentThreadInfo, &taskStructPtr, sizeof(taskStructPtr))) {
        return -1;
    }

    return taskStructPtr;
}

uint64_t DecreeMonitor::getMaxValue(S2EExecutionState *state, ref<Expr> value) {
    std::pair<ref<Expr>, ref<Expr>> range;
    Query query(state->constraints(), value);

    range = state->solver()->getRange(query);

    return dyn_cast<ConstantExpr>(range.second)->getZExtValue();
}

void DecreeMonitor::handleSymbolicSize(S2EExecutionState *state, uint64_t pid, uint64_t safeLimit,
                                       klee::ref<klee::Expr> size, uint64_t sizeAddr) {
    if (state->isRunningConcrete()) {
        getDebugStream(state) << "Switching to symbolic mode\n";
        state->jumpToSymbolicCpp();
        pabort("Unreachable code");
    }

    // Override symbolic size variable with its maximum possible concrete value.
    // This prevents forking in kernel memory functions, still allowing binary
    // to fork on symbolic size.
    //
    // Additionally, fork a state where symbolic size has a reasonable upper bound.
    // This is to handle cases where maximum possible concrete value is too big.

    ref<Expr> sizeIsSafe = E_LE(size, E_CONST(safeLimit, state->getPointerWidth()));

    bool isSeedState = m_seedSearcher ? m_seedSearcher->isSeedState(state) : false;
    s2e_assert(state, !isSeedState, "Concolics will be recomputed because of keepConditionTrueInCurrentState=true");

    Executor::StatePair sp = s2e()->getExecutor()->forkCondition(state, sizeIsSafe, true);

    if (sp.first) {
        S2EExecutionState *s = dynamic_cast<S2EExecutionState *>(sp.first);
        s2e_assert(s, s->isActive(), "S2EExecutionState::writePointer requires state to be active");

        uint64_t max = getMaxValue(s, size);
        s2e_assert(s, max <= safeLimit, "Solver must be wrong about max size value " << hexval(max));

        bool ok = s->writePointer(sizeAddr, max);
        s2e_assert(s, ok, "Failed to write memory");

        getDebugStream(s) << "Using size " << hexval(max) << "\n";
    }

    if (sp.second) {
        S2EExecutionState *s = dynamic_cast<S2EExecutionState *>(sp.second);

        getDebugStream(s) << "Size may be too big, leaving it symbolic\n";
    }
}

void DecreeMonitor::handleSymbolicAllocateSize(S2EExecutionState *state, uint64_t pid,
                                               const S2E_DECREEMON_COMMAND_HANDLE_SYMBOLIC_SIZE &d) {
    ref<Expr> size = state->mem()->read(d.size_addr, state->getPointerWidth());
    s2e_assert(state, size, "Failed to read memory");

    if (isa<ConstantExpr>(size)) {
        return;
    }

    getDebugStream(state) << "Symbolic allocate size in pid=" << hexval(pid) << "\n";

    if (!m_handleSymbolicAllocateSize) {
        return;
    }

    bool isSeedState = m_seedSearcher ? m_seedSearcher->isSeedState(state) : false;
    if (isSeedState) {
        return;
    }

    handleSymbolicSize(state, pid, decree::SAFE_ALLOCATE_SIZE, size, d.size_addr);
}

void DecreeMonitor::handleSymbolicBuffer(S2EExecutionState *state, uint64_t pid, SymbolicBufferType type,
                                         uint64_t ptrAddr, uint64_t sizeAddr) {
    ref<Expr> ptr = state->mem()->read(ptrAddr, state->getPointerWidth());
    s2e_assert(state, ptr, "Failed to read memory");

    ref<Expr> size = state->mem()->read(sizeAddr, state->getPointerWidth());
    s2e_assert(state, size, "Failed to read memory");

    bool isSymPtr = !isa<ConstantExpr>(ptr);
    bool isSymSize = !isa<ConstantExpr>(size);

    if (isSymPtr) {
        getDebugStream(state) << "Symbolic " << type << " buffer pointer in pid=" << hexval(pid) << "\n";
        onSymbolicBuffer.emit(state, pid, type, ptr, size);
    } else if (isSymSize) {
        getDebugStream(state) << "Symbolic " << type << " buffer size in pid=" << hexval(pid) << "\n";

        if (!m_handleSymbolicBufferSize) {
            return;
        }

        bool isSeedState = m_seedSearcher ? m_seedSearcher->isSeedState(state) : false;
        if (isSeedState) {
            return;
        }

        bool writable = bufferMustBeWritable(type);
        uint64_t ptrVal = dyn_cast<ConstantExpr>(ptr)->getZExtValue();

        uint64_t regionStart, regionEnd;
        MemoryMapRegionType regionType;

        bool res = m_map->lookupRegion(state, pid, ptrVal, regionStart, regionEnd, regionType);
        if (!res || (writable && !(regionType & MM_WRITE))) {
            return;
        }

        // Get the distance from ptrVal to the first unmapped page.
        // XXX: lookupRegion will return contiguous regions of the same type,
        // we might need to handle cases when next region is mapped but has
        // different flags.
        assert(regionEnd > ptrVal);
        uint64_t safeSize = regionEnd - ptrVal;
        if (!safeSize) {
            getDebugStream(state) << "no memory in buffer at " << hexval(ptrVal) << "\n";
            return;
        }

        handleSymbolicSize(state, pid, safeSize, size, sizeAddr);
    }
}

void DecreeMonitor::handleSymbolicReceiveBuffer(S2EExecutionState *state, uint64_t pid,
                                                const S2E_DECREEMON_COMMAND_HANDLE_SYMBOLIC_BUFFER &d) {
    handleSymbolicBuffer(state, pid, SYMBUFF_RECEIVE, d.ptr_addr, d.size_addr);
}

void DecreeMonitor::handleSymbolicTransmitBuffer(S2EExecutionState *state, uint64_t pid,
                                                 const S2E_DECREEMON_COMMAND_HANDLE_SYMBOLIC_BUFFER &d) {
    handleSymbolicBuffer(state, pid, SYMBUFF_TRANSMIT, d.ptr_addr, d.size_addr);
}

void DecreeMonitor::handleSymbolicRandomBuffer(S2EExecutionState *state, uint64_t pid,
                                               const S2E_DECREEMON_COMMAND_HANDLE_SYMBOLIC_BUFFER &d) {
    handleSymbolicBuffer(state, pid, SYMBUFF_RANDOM, d.ptr_addr, d.size_addr);
}

///
/// \brief Read and writes CB parameters
///
/// This handler is called by the CB loader right after it parsed CB parameters.
/// It is possible to modify passed parameters.
///
/// \param state current state
/// \param pid PID of related process
/// \param d command data
///
void DecreeMonitor::handleSetParams(S2EExecutionState *state, uint64_t pid, S2E_DECREEMON_COMMAND_SET_CB_PARAMS &d) {
    auto &ss = getDebugStream(state);
    ss << "CB parameters: "
       << " cgc_max_receive: " << d.cgc_max_receive << " cgc_max_transmit: " << d.cgc_max_transmit
       << " skip_rng_count: " << d.skip_rng_count << " cgc_seed_ptr: " << hexval(d.cgc_seed_ptr)
       << " cgc_seed_len: " << d.cgc_seed_len;

    // This part prints the input seed.
    if (d.cgc_seed_ptr) {
        // Truncate the seed if it's too long.
        // This would normally never happen with CGC binaries whose seeds are 48 byte long,
        // but it is still good practice to check external inputs for sanity.
        unsigned len = d.cgc_seed_len;
        if (len > sizeof(d.cgc_seed)) {
            len = sizeof(d.cgc_seed);
        }
        uint8_t buffer[len];
        memset(buffer, 0, len);

        if (!state->mem()->read(d.cgc_seed_ptr, buffer, len)) {
            ss << "\n";
            getWarningsStream(state) << "Could not read seed\n";
        } else {
            ss << " seed: ";
            for (unsigned i = 0; i < len; ++i) {
                ss << hexval(buffer[i]) << " ";
            }
            ss << "\n";
        }
    } else {
        ss << "\n";
    }

    // Set output seed
    // TODO: Make this configurable. For now set it to all zeros.
    // CGC loader uses 48 byte seeds.
    const char newSeed[S2E_DECREEMON_DECREE_SEED_SIZE] = {0};

    // Can use this to double check the seed correctness.
    // The cgc loader will print the first skip_rng_count random values.
    // Don't use this in production.
    // d.skip_rng_count = 16;

    d.cgc_seed_len = sizeof(newSeed);
    memcpy(d.cgc_seed, newSeed, d.cgc_seed_len);
}

void DecreeMonitor::printOpcodeOffsets(S2EExecutionState *state) {
    getDebugStream(state) << "S2E_DECREEMON_COMMAND offsets:\n";

#define PRINTOFF(field)                                                                                          \
    do {                                                                                                         \
        off_t off = offsetof(S2E_DECREEMON_COMMAND, field);                                                      \
        size_t sz = sizeof(S2E_DECREEMON_COMMAND::field);                                                        \
        getDebugStream(state) << "  " << hexval(off, 2) << ".." << hexval(off + sz, 2) << " " << #field << "\n"; \
    } while (0)

    PRINTOFF(Command);

    PRINTOFF(Data.fd);
    PRINTOFF(Data.buffer);
    PRINTOFF(Data.buffer_size);
    PRINTOFF(Data.size_expr_addr);
    PRINTOFF(Data.result_addr);

    PRINTOFF(DataPost.fd);
    PRINTOFF(DataPost.buffer);
    PRINTOFF(DataPost.buffer_size);

    PRINTOFF(WriteData.fd);
    PRINTOFF(WriteData.buffer);
    PRINTOFF(WriteData.buffer_size_addr);
    PRINTOFF(WriteData.size_expr_addr);

    PRINTOFF(FDWait.tv_sec);
    PRINTOFF(FDWait.tv_nsec);
    PRINTOFF(FDWait.has_timeout);
    PRINTOFF(FDWait.nfds);
    PRINTOFF(FDWait.invoke_orig);
    PRINTOFF(FDWait.result);

    PRINTOFF(Random.buffer);
    PRINTOFF(Random.buffer_size);

    PRINTOFF(GetCfgBool.key_addr);
    PRINTOFF(GetCfgBool.value);

    PRINTOFF(SymbolicSize.size_addr);

    PRINTOFF(SymbolicBuffer.ptr_addr);
    PRINTOFF(SymbolicBuffer.size_addr);
}

void DecreeMonitor::onSegFault(S2EExecutionState *state, uint64_t pid, const S2E_LINUXMON_COMMAND_SEG_FAULT &data) {
    if (m_firstSegfault) {
        time_t now;
        time(&now);
        m_timeToFirstSegfault = difftime(now, m_startTime);
        m_firstSegfault = false;
    }
}

void DecreeMonitor::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
    uint64_t commandSize = sizeof(S2E_DECREEMON_COMMAND);
    uint64_t commandVersion = S2E_DECREEMON_COMMAND_VERSION;
    uint8_t cmd[guestDataSize];
    memset(cmd, 0, guestDataSize);

    // Validate the size of the instruction
    s2e_assert(state, guestDataSize == commandSize,
               "Invalid command size " << guestDataSize << " != " << commandSize
                                       << " from pagedir=" << hexval(state->regs()->getPageDir())
                                       << " pc=" << hexval(state->regs()->getPc()));

    // Read any symbolic bytes
    std::ostringstream symbolicBytes;
    for (unsigned i = 0; i < guestDataSize; ++i) {
        ref<Expr> t = state->mem()->read(guestDataPtr + i);
        if (t && !isa<ConstantExpr>(t)) {
            symbolicBytes << "  " << hexval(i, 2) << "\n";
        }
    }

    if (symbolicBytes.str().length()) {
        getWarningsStream(state) << "Command has symbolic bytes at " << symbolicBytes.str() << "\n";
    }

    // Read the instruction
    bool ok = state->mem()->read(guestDataPtr, cmd, guestDataSize);
    s2e_assert(state, ok, "Failed to read instruction memory");

    // Validate the instruction's version

    // The version field comes always first in all commands
    uint64_t version = *(uint64_t *) cmd;

    if (version != commandVersion) {
        std::ostringstream os;

        for (unsigned i = 0; i < guestDataSize; ++i) {
            os << hexval(cmd[i]) << " ";
        }

        getWarningsStream(state) << "Command bytes: " << os.str() << "\n";

        s2e_assert(state, false,
                   "Invalid command version " << hexval(version) << " != " << hexval(commandVersion)
                                              << " from pagedir=" << hexval(state->regs()->getPageDir())
                                              << " pc=" << hexval(state->regs()->getPc()));
    }

    handleCommand(state, guestDataPtr, guestDataSize, cmd);
}

void DecreeMonitor::handleCommand(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize, void *cmd) {
    S2E_DECREEMON_COMMAND &command = *(S2E_DECREEMON_COMMAND *) cmd;

    auto pid = m_monitor->getPid(state);

    switch (command.Command) {
        case DECREE_READ_DATA: {
            handleReadData(state, pid, command.Data);
        } break;

        case DECREE_READ_DATA_POST: {
            handleReadDataPost(state, pid, command.DataPost);
        } break;

        case DECREE_WRITE_DATA: {
            handleWriteData(state, pid, command.WriteData);
        } break;

        case DECREE_FD_WAIT: {
            handleFdWait(state, command, guestDataPtr);
        } break;

        case DECREE_RANDOM: {
            handleRandom(state, pid, command.Random);
        } break;

        case DECREE_CONCOLIC_ON: {
            getDebugStream(state) << "Turning concolic execution on\n";
            DECLARE_PLUGINSTATE(DecreeMonitorState, state);
            plgState->m_concolicMode = true;
            plgState->m_invokeOriginalSyscalls = true;
        } break;

        case DECREE_CONCOLIC_OFF: {
            getDebugStream(state) << "Turning concolic execution off\n";
            DECLARE_PLUGINSTATE(DecreeMonitorState, state);
            plgState->m_concolicMode = false;
            plgState->m_invokeOriginalSyscalls = false;
        } break;

        case DECREE_GET_CFG_BOOL: {
            handleGetCfgBool(state, pid, command.GetCfgBool);
            bool ok = state->mem()->write(guestDataPtr, &command, sizeof(command));
            s2e_assert(state, ok, "Failed to write memory");
        } break;

        case DECREE_HANDLE_SYMBOLIC_ALLOCATE_SIZE: {
            handleSymbolicAllocateSize(state, pid, command.SymbolicSize);
        } break;

        case DECREE_HANDLE_SYMBOLIC_TRANSMIT_BUFFER: {
            handleSymbolicTransmitBuffer(state, pid, command.SymbolicBuffer);
        } break;

        case DECREE_HANDLE_SYMBOLIC_RECEIVE_BUFFER: {
            handleSymbolicReceiveBuffer(state, pid, command.SymbolicBuffer);
        } break;

        case DECREE_HANDLE_SYMBOLIC_RANDOM_BUFFER: {
            handleSymbolicRandomBuffer(state, pid, command.SymbolicBuffer);
        } break;

        case DECREE_SET_CB_PARAMS: {
            handleSetParams(state, pid, command.CbParams);
            if (!state->mem()->write(guestDataPtr, &command, guestDataSize)) {
                // Do not kill the state in case of an error here. This would prevent
                // any exploration at all.
                //
                // Incorrect seed might make fuzzer's task replaying S2E's test cases
                // a bit harder, it's not a show stopper.
                s2e_warn_assert(state, false, "Could not write new seed params");
            }
        } break;
    }
}

bool DecreeMonitor::isReadFd(uint32_t fd) {
    // fd 0 and 1 can both be read from interchangeably in CBs,
    // 3 is for cb-test, >=4 is for multibin CBs.
    if (fd == 0 || fd == 1) {
        return true;
    } else {
        return false;
    }
}

bool DecreeMonitor::isWriteFd(uint32_t fd) {
    // fd 0 and 1 can both be written to interchangeably in CBs,
    // 3 is for cb-test, >=4 is for multibin CBs.
    if (fd == 0 || fd == 1) {
        return true;
    } else {
        return false;
    }
}

} // namespace plugins
} // namespace s2e
