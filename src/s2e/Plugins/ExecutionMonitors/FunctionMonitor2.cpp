///
/// Copyright (C) 2015-2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/cpu.h>

#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>

#include <llvm/ADT/DenseSet.h>

#include "FunctionMonitor2.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(FunctionMonitor2, "Function monitoring plugin", "", "ExecutionTracer", "ProcessExecutionDetector",
                  "OSMonitor", "ModuleMap");

namespace {
class FunctionMonitor2State : public PluginState {
    // Maps a stack pointer containing a return address to the return signal
    using ReturnSignals = std::unordered_map<uint64_t, FunctionMonitor2::ReturnSignalPtr>;
    using PidRetSignals = std::unordered_map<uint64_t /* pid */, ReturnSignals>;

    PidRetSignals m_signals;

public:
    FunctionMonitor2State() {
    }
    virtual ~FunctionMonitor2State() {
    }
    virtual FunctionMonitor2State *clone() const {
        return new FunctionMonitor2State(*this);
    }
    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new FunctionMonitor2State();
    }

    void setReturnSignal(uint64_t pid, uint64_t sp, FunctionMonitor2::ReturnSignalPtr &signal) {
        m_signals[pid][sp] = signal;
    }

    FunctionMonitor2::ReturnSignalPtr getReturnSignal(uint64_t pid, uint64_t sp) const {
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
}

void FunctionMonitor2::initialize() {
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
    m_monitor->onProcessUnload.connect(sigc::mem_fun(*this, &FunctionMonitor2::onProcessUnload));
    m_monitor->onThreadExit.connect(sigc::mem_fun(*this, &FunctionMonitor2::onThreadExit));

    m_map = s2e()->getPlugin<ModuleMap>();
    m_processDetector = s2e()->getPlugin<ProcessExecutionDetector>();

    s2e()->getCorePlugin()->onTranslateBlockEnd.connect(sigc::mem_fun(*this, &FunctionMonitor2::onTranslateBlockEnd));
}

void FunctionMonitor2::onProcessUnload(S2EExecutionState *state, uint64_t addressSpace, uint64_t pid,
                                       uint64_t returnCode) {
    DECLARE_PLUGINSTATE(FunctionMonitor2State, state);
    plgState->erasePid(pid);
}

void FunctionMonitor2::onThreadExit(S2EExecutionState *state, const ThreadDescriptor &thread) {
    DECLARE_PLUGINSTATE(FunctionMonitor2State, state);
    // TODO: the monitor doesn't give info about user stack, only kernel one, so erase that one.
    plgState->eraseReturnSignals(thread.Pid, thread.KernelStackBottom, thread.KernelStackSize);
}

void FunctionMonitor2::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                           uint64_t pc, bool isStatic, uint64_t staticTarget) {
    if (m_monitor->isKernelAddress(pc)) {
        return;
    }

    if (tb->se_tb_type == TB_CALL || tb->se_tb_type == TB_CALL_IND) {
        signal->connect(sigc::mem_fun(*this, &FunctionMonitor2::onFunctionCall));
    } else if (tb->se_tb_type == TB_RET) {
        signal->connect(sigc::mem_fun(*this, &FunctionMonitor2::onFunctionReturn));
    }
}

void FunctionMonitor2::onFunctionCall(S2EExecutionState *state, uint64_t callerPc) {
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

    auto onRetSig = new FunctionMonitor2::ReturnSignal();
    auto onRetSigPtr = std::shared_ptr<FunctionMonitor2::ReturnSignal>(onRetSig);
    onCall.emit(state, callerMod, calleeMod, callerPc, calleePc, onRetSigPtr);
    if (!onRetSigPtr->empty()) {
        DECLARE_PLUGINSTATE(FunctionMonitor2State, state);
        auto pid = m_monitor->getPid(state);
        plgState->setReturnSignal(pid, state->regs()->getSp(), onRetSigPtr);
    }
}

void FunctionMonitor2::onFunctionReturn(S2EExecutionState *state, uint64_t returnPc) {
    if (!m_processDetector->isTracked(state)) {
        return;
    }

    DECLARE_PLUGINSTATE(FunctionMonitor2State, state);
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
