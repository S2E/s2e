///
/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/cpu.h>

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <iostream>

#include "FunctionMonitor.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(FunctionMonitor, "Function calls/returns monitoring plugin", "", );

void FunctionMonitor::initialize() {
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();

    m_localCalls = s2e()->getConfig()->getBool(getConfigKey() + ".monitorLocalFunctions");

    if (m_localCalls) {
        if (!m_detector) {
            getWarningsStream() << "FunctionMonitor: requires ModuleExecutionDetector when"
                                << " monitorLocalFunctions is true\n";
            exit(-1);
        }
        m_detector->onModuleTranslateBlockEnd.connect(
            sigc::mem_fun(*this, &FunctionMonitor::slotModuleTranslateBlockEnd));

        s2e()->getCorePlugin()->onTranslateJumpStart.connect(
            sigc::mem_fun(*this, &FunctionMonitor::slotTranslateJumpStart));

    } else {
        s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
            sigc::mem_fun(*this, &FunctionMonitor::slotTranslateBlockEnd));

        s2e()->getCorePlugin()->onTranslateJumpStart.connect(
            sigc::mem_fun(*this, &FunctionMonitor::slotTranslateJumpStart));
    }
}

// XXX: Implement onmoduleunload to automatically clear all call signals
FunctionMonitor::CallSignal *FunctionMonitor::getCallSignal(S2EExecutionState *state, uint64_t eip, uint64_t cr3) {
    DECLARE_PLUGINSTATE(FunctionMonitorState, state);

    return plgState->getCallSignal(eip, cr3);
}

void FunctionMonitor::slotModuleTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                  const ModuleDescriptor &module, TranslationBlock *tb, uint64_t pc,
                                                  bool isStatic, uint64_t staticTarget) {
    slotTranslateBlockEnd(signal, state, tb, pc, isStatic, staticTarget);
}

void FunctionMonitor::slotTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                            uint64_t pc, bool isStatic, uint64_t staticTarget) {
    /* We intercept all call and ret translation blocks */
    if (tb->se_tb_type == TB_CALL || tb->se_tb_type == TB_CALL_IND) {
        signal->connect(sigc::mem_fun(*this, &FunctionMonitor::slotCall));
    }
}

void FunctionMonitor::slotTranslateJumpStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *,
                                             uint64_t, int jump_type) {
    if (jump_type == JT_RET || jump_type == JT_LRET) {
        if (!m_localCalls || m_detector->getCurrentDescriptor(state)) {
            signal->connect(sigc::mem_fun(*this, &FunctionMonitor::slotRet));
        }
    }
}

void FunctionMonitor::slotCall(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(FunctionMonitorState, state);

    return plgState->slotCall(state, pc);
}

void FunctionMonitor::disconnect(S2EExecutionState *state, const ModuleDescriptor &desc) {
    DECLARE_PLUGINSTATE(FunctionMonitorState, state);

    return plgState->disconnect(desc);
}

// See notes for slotRet to see how to use this function.
void FunctionMonitor::eraseSp(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(FunctionMonitorState, state);

    return plgState->slotRet(state, pc, false);
}

void FunctionMonitor::registerReturnSignal(S2EExecutionState *state, FunctionMonitor::ReturnSignal &sig) {
    DECLARE_PLUGINSTATE(FunctionMonitorState, state);
    plgState->registerReturnSignal(state, sig);
}

void FunctionMonitor::slotRet(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(FunctionMonitorState, state);

    return plgState->slotRet(state, pc, true);
}

FunctionMonitorState::FunctionMonitorState() {
}

FunctionMonitorState::~FunctionMonitorState() {
}

FunctionMonitorState *FunctionMonitorState::clone() const {
    FunctionMonitorState *ret = new FunctionMonitorState(*this);
    assert(ret->m_returnDescriptors.size() == m_returnDescriptors.size());
    return ret;
}

PluginState *FunctionMonitorState::factory(Plugin *p, S2EExecutionState *s) {
    FunctionMonitorState *ret = new FunctionMonitorState();
    ret->m_plugin = static_cast<FunctionMonitor *>(p);
    return ret;
}

FunctionMonitor::CallSignal *FunctionMonitorState::getCallSignal(uint64_t eip, uint64_t cr3) {
    std::pair<CallDescriptorsMap::iterator, CallDescriptorsMap::iterator> range = m_callDescriptors.equal_range(eip);

    for (CallDescriptorsMap::iterator it = range.first; it != range.second; ++it) {
        if (it->second.cr3 == cr3)
            return &it->second.signal;
    }

    CallDescriptor descriptor = {cr3, FunctionMonitor::CallSignal()};
    CallDescriptorsMap::iterator it = m_newCallDescriptors.insert(std::make_pair(eip, descriptor));

    return &it->second.signal;
}

void FunctionMonitorState::slotCall(S2EExecutionState *state, uint64_t pc) {
    target_ulong cr3 = state->getPageDir();
    target_ulong eip = state->getPc();

    if (!m_newCallDescriptors.empty()) {
        m_callDescriptors.insert(m_newCallDescriptors.begin(), m_newCallDescriptors.end());
        m_newCallDescriptors.clear();
    }

    /* Issue signals attached to all calls (eip==-1 means catch-all) */
    if (!m_callDescriptors.empty()) {
        std::pair<CallDescriptorsMap::iterator, CallDescriptorsMap::iterator> range =
            m_callDescriptors.equal_range((uint64_t) -1);
        for (CallDescriptorsMap::iterator it = range.first; it != range.second; ++it) {
            CallDescriptor cd = (*it).second;
            if (m_plugin->m_monitor) {
                cr3 = m_plugin->m_monitor->getPageDir(state, pc);
            }
            if (it->second.cr3 == (uint64_t) -1 || it->second.cr3 == cr3) {
                cd.signal.emit(state, this);
            }
        }
        if (!m_newCallDescriptors.empty()) {
            m_callDescriptors.insert(m_newCallDescriptors.begin(), m_newCallDescriptors.end());
            m_newCallDescriptors.clear();
        }
    }

    /* Issue signals attached to specific calls */
    if (!m_callDescriptors.empty()) {
        std::pair<CallDescriptorsMap::iterator, CallDescriptorsMap::iterator> range;

        range = m_callDescriptors.equal_range(eip);
        for (CallDescriptorsMap::iterator it = range.first; it != range.second; ++it) {
            CallDescriptor cd = (*it).second;
            if (m_plugin->m_monitor) {
                cr3 = m_plugin->m_monitor->getPageDir(state, pc);
            }
            if (it->second.cr3 == (uint64_t) -1 || it->second.cr3 == cr3) {
                cd.signal.emit(state, this);
            }
        }
        if (!m_newCallDescriptors.empty()) {
            m_callDescriptors.insert(m_newCallDescriptors.begin(), m_newCallDescriptors.end());
            m_newCallDescriptors.clear();
        }
    }
}

/**
 *  A call handler can invoke this function to register a return handler.
 *  XXX: We assume that the passed execution state corresponds to the state in which
 *  this instance of FunctionMonitorState is used.
 */
void FunctionMonitorState::registerReturnSignal(S2EExecutionState *state, FunctionMonitor::ReturnSignal &sig) {
    if (sig.empty()) {
        return;
    }

    target_ulong esp;

    bool ok = state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ESP]), &esp, sizeof esp);
    if (!ok) {
        m_plugin->getWarningsStream(state) << "Function call with symbolic ESP!\n"
                                           << "  EIP=" << hexval(state->getPc())
                                           << " CR3=" << hexval(state->getPageDir()) << '\n';
        return;
    }

    uint64_t cr3 = state->getPageDir();
    if (m_plugin->m_monitor) {
        cr3 = m_plugin->m_monitor->getPageDir(state, state->getPc());
    }
    ReturnDescriptor descriptor = {cr3, sig};
    m_returnDescriptors.insert(std::make_pair(esp, descriptor));
}

/**
 *  When emitSignal is false, this function simply removes all the return descriptors
 * for the current stack pointer. This can be used when a return handler manually changes the
 * program counter and/or wants to exit to the cpu loop and avoid being called again.
 *
 *  Note: all the return handlers will be erased if emitSignal is false, not just the one
 * that issued the call. Also note that it not possible to return from the handler normally
 * whenever this function is called from within a return handler.
 */
void FunctionMonitorState::slotRet(S2EExecutionState *state, uint64_t pc, bool emitSignal) {
    target_ulong cr3 = state->regs()->read<target_ulong>(CPU_OFFSET(cr[3]));

    target_ulong esp;
    bool ok = state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ESP]), &esp, sizeof(target_ulong));
    if (!ok) {
        target_ulong eip = state->regs()->read<target_ulong>(CPU_OFFSET(eip));

        m_plugin->getWarningsStream(state) << "Function return with symbolic ESP!" << '\n'
                                           << "  EIP=" << hexval(eip) << " CR3=" << hexval(cr3) << '\n';
        return;
    }

    if (m_returnDescriptors.empty()) {
        return;
    }

    // m_plugin->getDebugStream() << "ESP AT RETURN 0x" << std::hex << esp <<
    //        " plgstate=0x" << this << " EmitSignal=" << emitSignal <<  std::endl;

    bool finished = true;
    do {
        finished = true;
        std::pair<ReturnDescriptorsMap::iterator, ReturnDescriptorsMap::iterator> range =
            m_returnDescriptors.equal_range(esp);
        for (ReturnDescriptorsMap::iterator it = range.first; it != range.second; ++it) {
            if (m_plugin->m_monitor) {
                cr3 = m_plugin->m_monitor->getAddressSpace(state, pc);
            }

            if (it->second.cr3 == cr3) {
                if (emitSignal) {
                    it->second.signal.emit(state);
                }
                m_returnDescriptors.erase(it);
                finished = false;
                break;
            }
        }
    } while (!finished);
}

void FunctionMonitorState::disconnect(const ModuleDescriptor &desc, CallDescriptorsMap &descMap) {
    CallDescriptorsMap::iterator it = descMap.begin();
    while (it != descMap.end()) {
        uint64_t addr = (*it).first;
        const CallDescriptor &call = (*it).second;
        if (desc.Contains(addr) && desc.AddressSpace == call.cr3) {
            CallDescriptorsMap::iterator it2 = it;
            ++it;
            descMap.erase(it2);
        } else {
            ++it;
        }
    }
}

// Disconnect all address that belong to desc.
// This is useful to unregister all handlers when a module is unloaded
void FunctionMonitorState::disconnect(const ModuleDescriptor &desc) {

    disconnect(desc, m_callDescriptors);
    disconnect(desc, m_newCallDescriptors);

    // XXX: we assume there are no more return descriptors active when the module is unloaded
}

} // namespace plugins
} // namespace s2e
