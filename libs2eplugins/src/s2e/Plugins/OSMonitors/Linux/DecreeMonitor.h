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

#ifndef S2E_PLUGINS_DECREE_MONITOR_H
#define S2E_PLUGINS_DECREE_MONITOR_H

#include <s2e/Plugin.h>
#include <s2e/S2E.h>

#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/Core/Vmi.h>
#include <s2e/Plugins/OSMonitors/Linux/LinuxMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/MemoryMap.h>

#include <s2e/monitors/commands/decree.h>

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/StringMap.h>
#include <llvm/ADT/StringRef.h>

namespace s2e {
namespace plugins {

class DecreeMonitorState;
class ProcessExecutionDetector;
class MemUtils;
class MemoryMap;

namespace seeds {
class SeedSearcher;
}

struct S2E_DECREEMON_VMA {
    uint64_t start;
    uint64_t end;
    uint64_t flags;
} __attribute__((packed));

template <typename T> T &operator<<(T &stream, const S2E_DECREEMON_VMA &v) {
    stream << hexval(v.start) << ".." << hexval(v.end) << " " << (v.flags & S2E_DECREEMON_VM_READ ? 'r' : '-')
           << (v.flags & S2E_DECREEMON_VM_WRITE ? 'w' : '-') << (v.flags & S2E_DECREEMON_VM_EXEC ? 'x' : '-');
    return stream;
}

template <typename T> T &operator<<(T &stream, const S2E_DECREEMON_COMMANDS &c) {
    switch (c) {
        case DECREE_READ_DATA:
            stream << "READ_DATA";
            break;
        case DECREE_WRITE_DATA:
            stream << "WRITE_DATA";
            break;
        case DECREE_FD_WAIT:
            stream << "FD_WAIT";
            break;
        case DECREE_RANDOM:
            stream << "RANDOM";
            break;
        case DECREE_READ_DATA_POST:
            stream << "READ_DATA_POST";
            break;
        case DECREE_CONCOLIC_ON:
            stream << "CONCOLIC_ON";
            break;
        case DECREE_CONCOLIC_OFF:
            stream << "CONCOLIC_OFF";
            break;
        case DECREE_GET_CFG_BOOL:
            stream << "GET_CFG_BOOL";
            break;
        case DECREE_HANDLE_SYMBOLIC_ALLOCATE_SIZE:
            stream << "HANDLE_SYMBOLIC_ALLOCATE_SIZE";
            break;
        case DECREE_HANDLE_SYMBOLIC_TRANSMIT_BUFFER:
            stream << "HANDLE_SYMBOLIC_TRANSMIT_BUFFER";
            break;
        case DECREE_HANDLE_SYMBOLIC_RECEIVE_BUFFER:
            stream << "HANDLE_SYMBOLIC_RECEIVE_BUFFER";
            break;
        case DECREE_HANDLE_SYMBOLIC_RANDOM_BUFFER:
            stream << "HANDLE_SYMBOLIC_RANDOM_BUFFER";
            break;
        case DECREE_SET_CB_PARAMS:
            stream << "SET_CB_PARAMS";
            break;
        default:
            stream << "INVALID(" << (int) c << ")";
            break;
    }
    return stream;
}

class DecreeMonitor : public Plugin, public IPluginInvoker {
    S2E_PLUGIN

    friend class DecreeMonitorState;

public:
    DecreeMonitor(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    double getTimeToFirstSegfault() {
        return m_timeToFirstSegfault;
    }

private:
    Vmi *m_vmi;
    MemoryMap *m_map;
    MemUtils *m_memutils;
    BaseInstructions *m_base;
    seeds::SeedSearcher *m_seedSearcher;
    LinuxMonitor *m_monitor;
    ProcessExecutionDetector *m_detector;

    llvm::DenseMap<uint64_t, llvm::StringRef> m_functionsMap;
    llvm::StringMap<uint64_t> m_functions;

    bool m_invokeOriginalSyscalls;

    bool m_printOpcodeOffsets;

    uint64_t m_symbolicReadLimitCount;
    uint64_t m_maxReadLimitCount;

    bool m_concolicMode;
    bool m_logWrittenData;
    bool m_handleSymbolicAllocateSize;
    bool m_handleSymbolicBufferSize;

    std::string m_feedConcreteData;

    time_t m_startTime;
    double m_timeToFirstSegfault;
    bool m_firstSegfault;

    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);

    void onLoadBinary(S2EExecutionState *state, uint64_t pc);
    void onLoadBinary_Return(S2EExecutionState *state, uint64_t pc);
    void onReceive(S2EExecutionState *state, uint64_t pc);
    void onSigSegv(S2EExecutionState *state, uint64_t pc);

public:
    enum SymbolicBufferType { SYMBUFF_RECEIVE, SYMBUFF_TRANSMIT, SYMBUFF_RANDOM };

    template <typename T> friend T &operator<<(T &stream, const SymbolicBufferType &type) {
        switch (type) {
            case SYMBUFF_RECEIVE:
                stream << "receive";
                break;
            case SYMBUFF_TRANSMIT:
                stream << "transmit";
                break;
            case SYMBUFF_RANDOM:
                stream << "random";
                break;
            default:
                stream << "INVALID";
                break;
        }
        return stream;
    }

    static bool bufferMustBeWritable(SymbolicBufferType t) {
        return t == SYMBUFF_RECEIVE || t == SYMBUFF_RANDOM;
    }

    sigc::signal<void, S2EExecutionState *, uint64_t /* pid */, uint64_t /* fd */,
                 const std::vector<klee::ref<klee::Expr>> & /* data */, klee::ref<klee::Expr> /* sizeExpr */
                 >
        onWrite;

    sigc::signal<void, S2EExecutionState *, uint64_t /* pid */, uint64_t /* fd */, uint64_t /* size */,
                 const std::vector<std::pair<std::vector<klee::ref<klee::Expr>>, std::string>> & /* data */,
                 klee::ref<klee::Expr> /* sizeExpr */
                 >
        onSymbolicRead;

    sigc::signal<void, S2EExecutionState *, uint64_t /* pid */, uint64_t /* fd */, const std::vector<uint8_t> &>
        onConcreteRead;

    sigc::signal<void, S2EExecutionState *, uint64_t /* pid */, const std::vector<klee::ref<klee::Expr>> & /* data */
                 >
        onRandom;

    /// \brief onSymbolicBuffer is emitted when a symbolic buffer is passed as
    /// argument to the system call
    ///
    /// This event will be emitted when buffer pointer is symbolic.
    sigc::signal<void, S2EExecutionState *, uint64_t /* pid */, SymbolicBufferType /* type */,
                 klee::ref<klee::Expr> /* ptr */, klee::ref<klee::Expr> /* size */
                 >
        onSymbolicBuffer;

    bool getFaultAddress(S2EExecutionState *state, uint64_t siginfo_ptr, uint64_t *address);

    void getPreFeedData(S2EExecutionState *state, uint64_t pid, uint64_t count, std::vector<uint8_t> &data);
    void getRandomData(S2EExecutionState *state, uint64_t count, std::vector<uint8_t> &data);
    klee::ref<klee::Expr> makeSymbolicRead(S2EExecutionState *state, uint64_t pid, uint64_t fd, uint64_t buf,
                                           uint64_t count, klee::ref<klee::Expr> countExpr);

    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);

    unsigned getSymbolicReadsCount(S2EExecutionState *state) const;

    static bool isReadFd(uint32_t fd);
    static bool isWriteFd(uint32_t fd);

private:
    target_ulong getTaskStructPtr(S2EExecutionState *state);

    void onSegFault(S2EExecutionState *state, uint64_t pid, const S2E_LINUXMON_COMMAND_SEG_FAULT &data);

    void handleCommand(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize, void *cmd);

    uint64_t getMaxValue(S2EExecutionState *state, klee::ref<klee::Expr> value);
    void handleSymbolicSize(S2EExecutionState *state, uint64_t pid, uint64_t safeLimit, klee::ref<klee::Expr> size,
                            uint64_t sizeAddr);
    void handleSymbolicBuffer(S2EExecutionState *state, uint64_t pid, SymbolicBufferType type, uint64_t ptrAddr,
                              uint64_t sizeAddr);

    void printOpcodeOffsets(S2EExecutionState *state);
    void handleReadData(S2EExecutionState *state, uint64_t pid, const S2E_DECREEMON_COMMAND_READ_DATA &d);
    void handleReadDataPost(S2EExecutionState *state, uint64_t pid, const S2E_DECREEMON_COMMAND_READ_DATA_POST &d);
    void handleWriteData(S2EExecutionState *state, uint64_t pid, const S2E_DECREEMON_COMMAND_WRITE_DATA &d);
    void handleFdWait(S2EExecutionState *state, S2E_DECREEMON_COMMAND &d, uintptr_t addr);
    void handleRandom(S2EExecutionState *state, uint64_t pid, const S2E_DECREEMON_COMMAND_RANDOM &d);
    void handleGetCfgBool(S2EExecutionState *state, uint64_t pid, S2E_DECREEMON_COMMAND_GET_CFG_BOOL &d);
    void handleSymbolicAllocateSize(S2EExecutionState *state, uint64_t pid,
                                    const S2E_DECREEMON_COMMAND_HANDLE_SYMBOLIC_SIZE &d);
    void handleSymbolicReceiveBuffer(S2EExecutionState *state, uint64_t pid,
                                     const S2E_DECREEMON_COMMAND_HANDLE_SYMBOLIC_BUFFER &d);
    void handleSymbolicTransmitBuffer(S2EExecutionState *state, uint64_t pid,
                                      const S2E_DECREEMON_COMMAND_HANDLE_SYMBOLIC_BUFFER &d);
    void handleSymbolicRandomBuffer(S2EExecutionState *state, uint64_t pid,
                                    const S2E_DECREEMON_COMMAND_HANDLE_SYMBOLIC_BUFFER &d);
    void handleSetParams(S2EExecutionState *state, uint64_t pid, S2E_DECREEMON_COMMAND_SET_CB_PARAMS &d);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_DECREE_MONITOR_H
