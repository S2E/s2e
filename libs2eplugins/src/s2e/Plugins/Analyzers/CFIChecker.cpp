///
/// Copyright (C) 2020, Vitaly Chipounov
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

#include <llvm/Support/raw_ostream.h>

#include <TraceEntries.pb.h>
#include <s2e/ConfigFile.h>
#include <s2e/FastReg.h>
#include <s2e/Plugins/ExecutionTracers/ExecutionTracer.h>
#include <s2e/Plugins/ExecutionTracers/UserSpaceTracer.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/MemoryMap.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsMonitor.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include "AddressTracker.h"
#include "CFIChecker.h"

#include <string.h>

extern "C" {
// When non-null, informs the translated code that call/return
// instrumentation must be called. This bypasses the normal plugin
// infrastructure for speed reasons. The speed of non-instrumented
// code should not be affected. If we didn't have this, we would
// have to use heavy-weight instrumentation for every single call/return
// in the system, considerably slowing down the analysis.
void *g_invokeCallRetInstrumentation;
}

namespace s2e {
namespace plugins {

void CFIStatistics::print(llvm::raw_ostream &os) const {
    os << "direct_calls: " << DirectCallCount << " indirect_calls: " << IndirectCallCount << " rets: " << RetCount
       << " call_violations: " << CallViolationCount << " ret_violations: " << RetViolationCount
       << " ret_from_unknown_exec_region: " << RetFromUnknownExecRegionCount
       << " ret_to_unknown_exec_region: " << RetToUnknownExecRegionCount << " ret_to_call_site: " << RetToCallSite
       << " missing_ret_addr: " << MissingReturnAddressCount << " call_ret_match: " << CallAndReturnMatchCount
       << " whitelisted_returns: " << WhitelistedReturnCount << " pending_violations: " << PendingViolationsCount
       << " whitelisted_call_patterns: " << WhitelistedCallPatternCount
       << " ret_to_parent_with_displacement: " << RetToParentWithDisplacement
       << " call_to_unknown_exec_region: " << CallToUnknownExecRegionCount << "\n";
}

void CFIStatistics::log(ExecutionTracer *tracer, S2EExecutionState *state) const {
    s2e_trace::PbTraceCfiStats item;

    item.set_direct_call_count(DirectCallCount);
    item.set_indirect_call_count(IndirectCallCount);
    item.set_ret_count(RetCount);
    item.set_call_violation_count(CallViolationCount);
    item.set_ret_violation_count(RetViolationCount);
    item.set_ret_from_unknown_exec_region_count(RetFromUnknownExecRegionCount);
    item.set_ret_to_call_site(RetToCallSite);
    item.set_ret_to_unknown_exec_region_count(RetToUnknownExecRegionCount);
    item.set_missing_return_address_count(MissingReturnAddressCount);
    item.set_call_and_return_match_count(CallAndReturnMatchCount);
    item.set_whitelisted_return_count(WhitelistedReturnCount);
    item.set_pending_violations_count(PendingViolationsCount);
    item.set_whitelisted_call_pattern_count(WhitelistedCallPatternCount);
    item.set_ret_to_parent_with_displacement_count(RetToParentWithDisplacement);
    item.set_call_to_unknown_exec_region_count(CallToUnknownExecRegionCount);

    tracer->writeData(state, item, s2e_trace::TRACE_CFI_STATS);
}

///
///@brief The shadow stack records return addresses for each call instruction.
///
class ShadowStack {
public:
    // This maps a stack pointer to the corresponding return address.
    // We use a map instead of an array to save memory, as there are not that
    // many return addresses on the stack anyway.
    using SparseStack = std::unordered_map<uint64_t, uint64_t>;

private:
    SparseStack m_stack;

public:
    inline void set(uint64_t guest_sp, uint64_t value) {
        m_stack[guest_sp] = value;
    }

    inline bool get(uint64_t guest_sp, uint64_t &value) const {
        auto it = m_stack.find(guest_sp);
        if (it == m_stack.end()) {
            return false;
        }
        value = it->second;
        return true;
    }

    inline void erase(uint64_t sp) {
        m_stack.erase(sp);
    }
};

///
///@brief Represents a CFI violation.
///
/// This structure contains all the useful information
/// about a control flow integrity violation.
///
struct CFIViolation {
    // Can be either a call or a return violation
    bool isReturnViolation = false;

    // The instruction that caused the violation.
    // Always an indirect call or a return.
    uint64_t sourcePc = 0;
    ModuleDescriptorConstPtr source;

    // The actual faulty destination of the source instruction.
    uint64_t destPc = 0;
    ModuleDescriptorConstPtr dest;

    // In case of a return violation, the expected address
    // that was recorded on the shadow stack.
    uint64_t expectedDestPc = 0;
    ModuleDescriptorConstPtr expectedDest;

    // Log the violation to a stream, typically debug.txt
    void log(llvm::raw_ostream &os, S2EExecutionState *state) const {
        std::string type = isReturnViolation ? "return" : "call";

        os << "Detected CFI " << type << " violation: actual=" << hexval(destPc);
        if (isReturnViolation) {
            os << " expected=" << hexval(expectedDestPc);
        }
        os << "\n";

        if (source) {
            uint64_t native = 0;
            source->ToNativeBase(sourcePc, native);
            os << "  source: " << source->Name << ":" << hexval(native) << "\n";
        }

        if (dest) {
            uint64_t native = 0;
            dest->ToNativeBase(destPc, native);
            os << "  actual destination: " << dest->Name << ":" << hexval(native) << "\n";
        }

        if (expectedDest) {
            uint64_t native = 0;
            expectedDest->ToNativeBase(expectedDestPc, native);
            os << "  expect destination: " << expectedDest->Name << ":" << hexval(native) << "\n";
        }

        std::string s1;
        llvm::raw_string_ostream ss1(s1);
        if (state->disassemble(ss1, destPc, 32)) {
            os << "Disassembly at " << hexval(destPc) << "\n";
            os << ss1.str() << "\n";
        } else {
            os << "Could not disassemble " << hexval(destPc) << "\n";
        }

        if (isReturnViolation) {
            std::string s2;
            llvm::raw_string_ostream ss2(s2);
            if (state->disassemble(ss2, expectedDestPc, 32)) {
                os << "Disassembly at " << hexval(expectedDestPc) << "\n";
                os << ss2.str() << "\n";
            } else {
                os << "Could not disassemble " << hexval(expectedDestPc) << "\n";
            }
        }
    }

    // Log the violation to the exection trace, which can then be dumped
    // using the "s2e execution_trace" tool.
    void log(ExecutionTracer *tracer, S2EExecutionState *state) const {
        s2e_trace::PbTraceCfiViolation v;
        v.set_type(isReturnViolation ? s2e_trace::RETURN_VIOLATION : s2e_trace::CALL_VIOLATION);

        auto s = new s2e_trace::PbTraceViolationPcInfo();
        s->set_pc(sourcePc);
        if (source) {
            uint64_t native = 0;
            source->ToNativeBase(sourcePc, native);
            s->set_module_pc(native);
            s->set_module_path(source->Path);
        }
        v.set_allocated_source(s);

        auto d = new s2e_trace::PbTraceViolationPcInfo();
        d->set_pc(destPc);
        if (dest) {
            uint64_t native = 0;
            dest->ToNativeBase(destPc, native);
            d->set_module_pc(native);
            d->set_module_path(dest->Path);
        }
        v.set_allocated_destination(d);

        if (expectedDestPc) {
            auto e = new s2e_trace::PbTraceViolationPcInfo();
            e->set_pc(expectedDestPc);
            if (expectedDest) {
                uint64_t native = 0;
                expectedDest->ToNativeBase(expectedDestPc, native);
                e->set_module_pc(native);
                e->set_module_path(expectedDest->Path);
            }
            v.set_allocated_expected_destination(e);
        }

        tracer->writeData(state, v, s2e_trace::TRACE_CFI_VIOLATION);
    }
};

using CFIViolations = std::vector<CFIViolation>;

///
///@brief CFICheckerState keeps track of per-state CFI data.
///
/// Its main purpose is to keep track of all the processes of interest
/// as well as their threads and associated stacks.
///
class CFICheckerState : public PluginState {
public:
    struct ThreadState {
        ShadowStack stack;

        CFIViolations pendingViolations;
        bool checkIfCallTargetIsWhitelisted;
    };

    using ThreadStatePtr = std::shared_ptr<ThreadState>;

    using ThreadStates = std::unordered_map<uint64_t /* tid */, ThreadStatePtr>;
    using Processes = std::unordered_map<uint64_t /* pid */, ThreadStates>;
    using PidTid = std::pair<uint64_t, uint64_t>;

private:
    Processes m_processes;

    uint64_t m_currentPid = 0;
    uint64_t m_currentTid = 0;

    // The actual CFI state is burried within several layers of maps.
    // In order to avoid overhead, this variable provides direct access
    // to the correct state associated with the current thread.
    ThreadStatePtr m_currentThreadState = nullptr;

    CFIStatistics m_stats;

public:
    void setPidTid(uint64_t pid, uint64_t tid) {
        m_currentPid = pid;
        m_currentTid = tid;
        m_currentThreadState = m_processes[pid][tid];
        if (!m_currentThreadState) {
            m_currentThreadState = std::make_shared<ThreadState>();
            m_processes[pid][tid] = m_currentThreadState;
        }
    }

    inline PidTid getPidTid() const {
        assert(m_currentPid && m_currentTid);
        return PidTid(m_currentPid, m_currentTid);
    }

    void removePid(uint64_t pid) {
        m_processes.erase(pid);
    }

    void removeTid(uint64_t pid, uint64_t tid) {
        auto it = m_processes.find(pid);
        if (it == m_processes.end()) {
            return;
        }
        it->second.erase(tid);
    }

    inline void set(uint64_t pid, uint64_t tid, uint64_t guest_sp, uint64_t value) {
        if (pid == m_currentPid && tid == m_currentTid && m_currentThreadState) {
            m_currentThreadState->stack.set(guest_sp, value);
        } else {
            m_processes[pid][tid]->stack.set(guest_sp, value);
        }
    }

    // TODO: optimize these methods. currentThreadState should always be up to date.
    inline bool get(uint64_t pid, uint64_t tid, uint64_t guest_sp, uint64_t &value) const {
        if (pid == m_currentPid && tid == m_currentTid && m_currentThreadState) {
            return m_currentThreadState->stack.get(guest_sp, value);
        }

        auto it = m_processes.find(pid);
        if (it == m_processes.end()) {
            return false;
        }

        auto tit = it->second.find(tid);
        if (tit == it->second.end()) {
            return false;
        }

        return tit->second->stack.get(guest_sp, value);
    }

    inline void erase(uint64_t pid, uint64_t tid, uint64_t guest_sp) {
        assert(pid == m_currentPid && tid == m_currentTid && m_currentThreadState);
        m_currentThreadState->stack.erase(guest_sp);
    }

    inline ThreadStatePtr get(uint64_t pid, uint64_t tid) {
        if (pid == m_currentPid && tid == m_currentTid && m_currentThreadState) {
            return m_currentThreadState;
        } else {
            return m_processes[pid][tid];
        }
    }

    inline ThreadStatePtr get() const {
        assert(m_currentPid && m_currentTid && m_currentThreadState);
        return m_currentThreadState;
    }

    inline uint64_t getCachedPid() const {
        return m_currentPid;
    }

    inline CFIStatistics &getStats() {
        return m_stats;
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new CFICheckerState();
    }

    virtual ~CFICheckerState() {
        // Destroy any object if needed
    }

    virtual CFICheckerState *clone() const {
        return new CFICheckerState(*this);
    }
};

S2E_DEFINE_PLUGIN(CFIChecker, "Describe what the plugin does here", "", "AddressTracker", "WindowsMonitor",
                  "ModuleMap");

static CFIChecker *s_checker;

void CFIChecker::initialize() {
    m_tracker = s2e()->getPlugin<AddressTracker>();
    m_process = s2e()->getPlugin<ProcessExecutionDetector>();
    m_monitor = s2e()->getPlugin<WindowsMonitor>();
    m_modules = s2e()->getPlugin<ModuleMap>();
    m_tracer = s2e()->getPlugin<ExecutionTracer>();
    m_userSpaceTracer = s2e()->getPlugin<UserSpaceTracer>();

    m_monitor->onMonitorLoad.connect(sigc::mem_fun(*this, &CFIChecker::onMonitorLoad));
    m_monitor->onProcessOrThreadSwitch.connect(sigc::mem_fun(*this, &CFIChecker::onProcessOrThreadSwitch));
    m_monitor->onProcessUnload.connect(sigc::mem_fun(*this, &CFIChecker::onProcessUnload));
    m_monitor->onThreadExit.connect(sigc::mem_fun(*this, &CFIChecker::onThreadExit));

    s2e()->getCorePlugin()->onTimer.connect(sigc::mem_fun(*this, &CFIChecker::onTimer));
    s2e()->getCorePlugin()->onStateKill.connect(sigc::mem_fun(*this, &CFIChecker::onStateKill));

    m_traceOnCfiViolation = s2e()->getConfig()->getBool(getConfigKey() + ".traceOnCfiViolation", false);
    if (m_traceOnCfiViolation) {
        if (!m_userSpaceTracer) {
            getDebugStream() << "traceOnCfiViolation requires UserSpaceTracer\n";
            exit(-1);
        }
    }

    s_checker = this;
}

void CFIChecker::onTimer(void) {
    DECLARE_PLUGINSTATE(CFICheckerState, g_s2e_state);
    auto &stats = plgState->getStats();
    auto &os = getDebugStream(g_s2e_state);
    stats.print(os);
    if (m_tracer) {
        stats.log(m_tracer, g_s2e_state);
    }
}

void CFIChecker::onStateKill(S2EExecutionState *state) {
    onTimer();
}

void CFIChecker::onMonitorLoad(S2EExecutionState *state) {
    s2e()->getCorePlugin()->onCallReturnTranslate.connect(sigc::mem_fun(*this, &CFIChecker::onCallReturnTranslate));
}

void CFIChecker::onProcessUnload(S2EExecutionState *state, uint64_t cr3, uint64_t pid, uint64_t returnCode) {
    DECLARE_PLUGINSTATE(CFICheckerState, state);
    plgState->removePid(pid);
}

void CFIChecker::onThreadExit(S2EExecutionState *state, const ThreadDescriptor &thread) {
    DECLARE_PLUGINSTATE(CFICheckerState, state);
    plgState->removeTid(thread.Pid, thread.Tid);
}

// This function is important to have acceptable performance.
// It decides whether the currently running thread must be instrumented or not.
void CFIChecker::onProcessOrThreadSwitch(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(CFICheckerState, state);

    auto pid = m_monitor->getCurrentProcessId(state);
    auto tid = m_monitor->getCurrentThreadId(state);

    plgState->setPidTid(pid, tid);

    auto isTracked = m_process->isTrackedPid(state, pid);
    g_invokeCallRetInstrumentation = isTracked ? (void *) 1 : nullptr;
}

void CFIChecker::onCallReturnTranslate(S2EExecutionState *state, uint64_t pc, bool isCall, bool *instrument) {
    if (m_monitor->isKernelAddress(pc)) { // XXX make it configurable
        return;
    }

    *instrument = true;
}

void CFIChecker::reportPendingViolations(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(CFICheckerState, state);
    auto ts = plgState->get();
    auto &stats = plgState->getStats();

    bool hasViolations = !ts->pendingViolations.empty();
    if (hasViolations) {
        if (m_traceOnCfiViolation) {
            m_userSpaceTracer->startTracing(state, m_monitor->getPid(state), m_monitor->getTid(state), 100);
        }
    }

    for (const auto &v : ts->pendingViolations) {
        v.log(getWarningsStream(state), state);

        if (v.isReturnViolation) {
            ++stats.RetViolationCount;
        } else {
            ++stats.CallViolationCount;
        }

        if (m_tracer) {
            v.log(m_tracer, state);
        }

        onCFIViolation.emit(state, v.isReturnViolation);
    }
}

// Handles every call instruction in the tracked processes
void CFIChecker::onCall(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(CFICheckerState, state);
    enum ETranslationBlockType se_tb_type = state->getTb()->se_tb_type;
    assert(se_tb_type == TB_CALL || se_tb_type == TB_CALL_IND);

    auto &stats = plgState->getStats();

    if (se_tb_type == TB_CALL) {
        ++stats.DirectCallCount;
    } else if (se_tb_type == TB_CALL_IND) {
        ++stats.IndirectCallCount;
    } else {
        assert(false && "Incorrect tb type");
    }

    // Record the return address on the shadow stack
    auto returnAddress = env->return_address;
    auto sp = state->regs()->getSp();
    auto ts = plgState->get();
    ts->stack.set(sp, returnAddress);

    auto target_pc = state->regs()->getPc();

    // See if we need to confirm any pending violation
    if (ts->checkIfCallTargetIsWhitelisted) {
        if (!isKnownFunctionPattern(state, target_pc)) {
            reportPendingViolations(state);
        } else {
            ++stats.WhitelistedCallPatternCount;
        }
        ts->checkIfCallTargetIsWhitelisted = false;
        ts->pendingViolations.clear();
    }

    // If we have a direct call, we are done
    if (se_tb_type != TB_CALL_IND) {
        return;
    }

    // Check that indirect calls go to a valid function
    auto pid = plgState->getCachedPid();
    if (m_tracker->isValidCallTarget(state, pid, target_pc)) {
        return;
    }

    // Weed out false positives
    CFIViolation violation;
    violation.destPc = target_pc;
    violation.dest = m_modules->getModule(state, target_pc);
    if (!violation.dest) {
        // Whitelist calls to unknown regions. These are usually JIT.
        ++stats.CallToUnknownExecRegionCount;
        return;
    }

    // TODO: skip calls to writable code segment (self-modifying)

    // Now we have confirmed violation, report it.
    violation.isReturnViolation = false;
    violation.sourcePc = pc;
    violation.source = m_modules->getModule(state, pc);

    ts->pendingViolations.push_back(violation);
    reportPendingViolations(state);
    ts->pendingViolations.clear();
}

struct Pattern {
    int size;
    const uint8_t pattern[32];
};

static const Pattern s_function_patterns[] = {
    //  __EH_epilog3
    // mov     ecx, [ebp-0Ch]
    // mov     large fs:0, ecx
    // pop     ecx
    // pop     edi
    // pop     edi
    // pop     esi
    // pop     ebx
    {15, {0x8B, 0x4D, 0xF4, 0x64, 0x89, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x59, 0x5F, 0x5F, 0x5E, 0x5B}},

    // __SEH_epilog4
    // mov     ecx, [ebp-10h]
    // mov     large fs:0, ecx
    // pop     ecx
    // pop     edi
    // pop     edi
    // pop     esi
    // pop     ebx
    // mov     esp, ebp
    // pop     ebp
    // push    ecx
    // ; retn | bndretn ; c3 / f2 c3, we only match common prefix
    {19,
     {0x8B, 0x4D, 0xF0, 0x64, 0x89, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x59, 0x5F, 0x5F, 0x5E, 0x5B, 0x8B, 0xE5, 0x5D,
      0x51}},

    {0, {}}};

bool CFIChecker::isKnownFunctionPattern(S2EExecutionState *state, uint64_t pc) {
    unsigned maxSize = 0;
    for (const auto *pattern = &s_function_patterns[0]; pattern->size; ++pattern) {
        if (pattern->size > maxSize) {
            maxSize = pattern->size;
        }
    }

    uint8_t buf[maxSize];
    if (!state->mem()->read(pc, buf, maxSize)) {
        return false;
    }

    for (const auto *pattern = &s_function_patterns[0]; pattern->size; ++pattern) {
        if (!::memcmp(pattern->pattern, buf, pattern->size)) {
            return true;
        }
    }

    return false;
}

// XXX: there may be FPs, e.g., other instructions might end
// with the same sequence. Need to cross check with translation block's
// precise pc array.
static const Pattern s_patterns[] = {
    // mov large fs:0, eax - winxp kernel32.dll SEH_prolog
    {6, {0x64, 0xa3, 0x00, 0x00, 0x00, 0x00}},

    // push ecx - winxp kernel32.dll SEH_epilog
    {1, {0x51}},

    // push eax - winxp rsaenh.dll
    {1, {0x50}},

    // popf - mso.dll on office10
    {1, {0x9d}},

    // chkstk in various DLLs on winxp
    // xchg    eax, esp
    // mov     eax, [eax]
    // push    eax
    // ;ret
    {4, {0x94, 0x8B, 0x00, 0x50}},

    // chkstk? wwlib.dll on office 2010
    // xchg    eax, esp
    // mov     eax, [eax]
    // mov     [esp], eax
    // ;ret
    {6, {0x94, 0x8B, 0x00, 0x89, 0x04, 0x24}},

    // sxs.dll on winxp
    // lea     ebp, [esp+0Ch]
    // push    eax
    // ;ret
    {5, {0x8D, 0x6C, 0x24, 0x0C, 0x50}},

    // Wow64PrepareForException
    // mov     rbx, [rsp+48h+var_18]
    // mov     rsi, [rsp+48h+var_10]
    // mov     rdi, [rsp+48h+var_8]
    // add     rsp, 48h
    // ; retn
    {19,
     {0x48, 0x8B, 0x5C, 0x24, 0x30, 0x48, 0x8B, 0x74, 0x24, 0x38, 0x48, 0x8B, 0x7C, 0x24, 0x40, 0x48, 0x83, 0xC4,
      0x48}},

    {0, {}}};

// Handles every return instruction in the tracked processes
void CFIChecker::onRet(S2EExecutionState *state, uint64_t pc, int retim_value) {
    DECLARE_PLUGINSTATE(CFICheckerState, state);

    auto &stats = plgState->getStats();
    ++stats.RetCount;

    // The plugin instruments ret when it is done executing, so current pc is the return address
    auto returnAddress = s2e_read_register_concrete_fast<target_ulong>(CPU_OFFSET(eip));
    auto pidTid = plgState->getPidTid();
    auto sp = state->regs()->getSp() - state->getPointerSize() - retim_value;

    // Check that the return address matches the one on the shadow stack
    uint64_t expectedReturnAddress;
    if (plgState->get(pidTid.first, pidTid.second, sp, expectedReturnAddress)) {
        plgState->erase(pidTid.first, pidTid.second, sp);
        if (returnAddress == expectedReturnAddress) {
            // Everything is ok
            ++stats.CallAndReturnMatchCount;
            return;
        }
    } else {
        ++stats.MissingReturnAddressCount;
    }

    // At this point, we either had no return address at all on the shadow stack,
    // or the return address did not match what a previous call has recorded.

    // Whitelist return instruction if it is part of a known function
    // that messes with the stack.
    for (const auto *pattern = &s_patterns[0]; pattern->size; ++pattern) {
        uint8_t buf[32];
        if (state->mem()->read(pc - pattern->size, buf, pattern->size)) {
            if (!::memcmp(pattern->pattern, buf, pattern->size)) {
                ++stats.WhitelistedReturnCount;
                return;
            }
        }
    }

    // Accept returns that go after some call site
    uint8_t callsite[5];
    if (state->mem()->read(returnAddress - sizeof(callsite), callsite, sizeof(callsite))) {
        if (callsite[0] == 0xe8) {
            // call immediate
            ++stats.RetToCallSite;
            return;
        } else if (callsite[0] == 0xff) {
            // call [mem]
            ++stats.RetToCallSite;
            return;
        } else if (callsite[3] == 0xff) {
            // call reg
            ++stats.RetToCallSite;
            return;
        }
    }

    CFIViolation violation;
    violation.isReturnViolation = true;
    violation.sourcePc = pc;
    violation.source = m_modules->getModule(state, pc);
    violation.destPc = returnAddress;
    violation.dest = m_modules->getModule(state, returnAddress);
    violation.expectedDestPc = expectedReturnAddress;
    violation.expectedDest = m_modules->getModule(state, expectedReturnAddress);

    // Hack for mso.dll in ms office
    // Note: this may be a source of false negatives in practice, e.g, when gadgets are close by.
    if (violation.dest && violation.expectedDest) {
        if (violation.dest->Name == violation.expectedDest->Name) {
            // There is weird code that does not return to instruction following a call,
            // but to some other places in that function.
            uint64_t diff = (uint64_t) abs((int64_t) returnAddress - (int64_t) expectedReturnAddress);
            if (diff <= 0x28) {
                ++stats.RetToParentWithDisplacement;
                return;
            }
        }
    }

    // Whitelist returns from/to unknown executable memory regions.
    // These are usually JIT code.
    if (!violation.source) {
        ++stats.RetFromUnknownExecRegionCount;
        return;
    }

    if (!violation.dest) {
        ++stats.RetToUnknownExecRegionCount;
        return;
    }

    auto hasViolations = stats.CallViolationCount > 0 || stats.RetViolationCount > 0;

    auto ts = plgState->get();
    if (hasViolations) {
        // Skip all the heuristics if we already had actual violations.
        // We don't care about FPs, we don't want FNs.
        ts->pendingViolations.push_back(violation);
        reportPendingViolations(state);
        ts->pendingViolations.clear();
        return;
    }

    // Need to execute a little more code to decide if what we've got
    // is a violation or not. The next call instruction will resolve this.
    ts->checkIfCallTargetIsWhitelisted = true;
    ts->pendingViolations.push_back(violation);
    ++stats.PendingViolationsCount;
}

const CFIStatistics &CFIChecker::getStats(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(CFICheckerState, state);
    return plgState->getStats();
}

// These two functions are directly callede from the translated code.
// They bypass S2E's plugin infrastructure for speed reasons.
// Note that it is not possible to have several plugins to use these.
// For now we only have CFIChecker.
extern "C" {
void helper_se_call(target_ulong pc) {
    s_checker->onCall(g_s2e_state, pc);
}

void helper_se_ret(target_ulong pc, int retim_value) {
    s_checker->onRet(g_s2e_state, pc, retim_value);
}
}

} // namespace plugins
} // namespace s2e
