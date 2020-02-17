///
/// Copyright (C) 2015-2019, Cyberhaven
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
#include <s2e/S2E.h>
#include <s2e/cpu.h>

#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>

#include <llvm/ADT/DenseSet.h>

#include "FunctionMonitor.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(FunctionMonitor, "Function monitoring plugin", "", "ProcessExecutionDetector", "OSMonitor",
                  "ModuleMap");

namespace {
class FunctionMonitorState : public PluginState {
    // Maps a stack pointer containing a return address to the return signal
    using ReturnSignals = std::unordered_map<uint64_t, FunctionMonitor::ReturnSignalPtr>;
    using PidRetSignals = std::unordered_map<uint64_t /* pid */, ReturnSignals>;

    PidRetSignals m_signals;

public:
    FunctionMonitorState() {
    }
    virtual ~FunctionMonitorState() {
    }
    virtual FunctionMonitorState *clone() const {
        return new FunctionMonitorState(*this);
    }
    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new FunctionMonitorState();
    }

    void setReturnSignal(uint64_t pid, uint64_t sp, FunctionMonitor::ReturnSignalPtr &signal) {
        m_signals[pid][sp] = signal;
    }

    FunctionMonitor::ReturnSignalPtr getReturnSignal(uint64_t pid, uint64_t sp) const {
        auto pit = m_signals.find(pid);
        if (pit == m_signals.end()) {
            return nullptr;
        }

        auto sit = pit->second.find(sp);
        if (sit == pit->second.end()) {
            return nullptr;
        }

        return sit->second;
    }

    void eraseReturnSignal(uint64_t pid, uint64_t sp) {
        auto it = m_signals.find(pid);
        if (it == m_signals.end()) {
            return;
        }
        it->second.erase(sp);
    }

    void eraseReturnSignals(uint64_t pid, uint64_t stackBottom, uint64_t stackSize) {
        auto sit = m_signals.find(pid);
        if (sit == m_signals.end()) {
            return;
        }

        llvm::DenseSet<uint64_t> toErase;
        auto end = stackBottom + stackSize;
        for (const auto &it : m_signals) {
            if (it.first >= stackBottom && it.first < end) {
                toErase.insert(it.first);
            }
        }

        for (auto sp : toErase) {
            sit->second.erase(sp);
        }
    }

    void erasePid(uint64_t pid) {
        m_signals.erase(pid);
    }
};
} // namespace

void FunctionMonitor::initialize() {
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
    m_monitor->onProcessUnload.connect(sigc::mem_fun(*this, &FunctionMonitor::onProcessUnload));
    m_monitor->onThreadExit.connect(sigc::mem_fun(*this, &FunctionMonitor::onThreadExit));

    m_map = s2e()->getPlugin<ModuleMap>();
    m_processDetector = s2e()->getPlugin<ProcessExecutionDetector>();

    s2e()->getCorePlugin()->onTranslateBlockEnd.connect(sigc::mem_fun(*this, &FunctionMonitor::onTranslateBlockEnd));
}

void FunctionMonitor::onProcessUnload(S2EExecutionState *state, uint64_t addressSpace, uint64_t pid,
                                      uint64_t returnCode) {
    DECLARE_PLUGINSTATE(FunctionMonitorState, state);
    plgState->erasePid(pid);
}

void FunctionMonitor::onThreadExit(S2EExecutionState *state, const ThreadDescriptor &thread) {
    DECLARE_PLUGINSTATE(FunctionMonitorState, state);
    // TODO: the monitor doesn't give info about user stack, only kernel one, so erase that one.
    plgState->eraseReturnSignals(thread.Pid, thread.KernelStackBottom, thread.KernelStackSize);
}

void FunctionMonitor::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                          uint64_t pc, bool isStatic, uint64_t staticTarget) {
    if (m_monitor->isKernelAddress(pc)) {
        return;
    }

    if (tb->se_tb_type == TB_CALL || tb->se_tb_type == TB_CALL_IND) {
        signal->connect(sigc::mem_fun(*this, &FunctionMonitor::onFunctionCall));
    } else if (tb->se_tb_type == TB_RET) {
        signal->connect(sigc::mem_fun(*this, &FunctionMonitor::onFunctionReturn));
    }
}

void FunctionMonitor::onFunctionCall(S2EExecutionState *state, uint64_t callerPc) {
    if (!m_processDetector->isTracked(state)) {
        return;
    }

    uint64_t calleePc = state->regs()->getPc();

    auto callerMod = m_map->getModule(state, callerPc);
    auto calleeMod = m_map->getModule(state, calleePc);

    bool ok = true;

    if (callerMod) {
        ok &= callerMod->ToNativeBase(callerPc, callerPc);
    }

    if (calleeMod) {
        ok &= calleeMod->ToNativeBase(calleePc, calleePc);
    }

    if (!ok) {
        getWarningsStream(state) << "Could not get relative caller/callee address\n";
        return;
    }

    auto onRetSig = new FunctionMonitor::ReturnSignal();
    auto onRetSigPtr = std::shared_ptr<FunctionMonitor::ReturnSignal>(onRetSig);
    onCall.emit(state, callerMod, calleeMod, callerPc, calleePc, onRetSigPtr);
    if (!onRetSigPtr->empty()) {
        DECLARE_PLUGINSTATE(FunctionMonitorState, state);
        auto pid = m_monitor->getPid(state);
        plgState->setReturnSignal(pid, state->regs()->getSp(), onRetSigPtr);
    }
}

void FunctionMonitor::onFunctionReturn(S2EExecutionState *state, uint64_t returnPc) {
    if (!m_processDetector->isTracked(state)) {
        return;
    }

    DECLARE_PLUGINSTATE(FunctionMonitorState, state);
    auto sp = state->regs()->getSp() - state->getPointerSize();
    auto pid = m_monitor->getPid(state);
    auto signal = plgState->getReturnSignal(pid, sp);
    if (!signal) {
        return;
    }

    uint64_t returnDestPc = state->regs()->getPc();

    auto sourceMod = m_map->getModule(state, returnPc);
    auto destMod = m_map->getModule(state, returnDestPc);

    signal->emit(state, sourceMod, destMod, returnPc);
    plgState->eraseReturnSignal(pid, sp);
}

} // namespace plugins
} // namespace s2e
