///
/// Copyright (C) 2015-2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_ARMFunctionMonitor_H
#define S2E_PLUGINS_ARMFunctionMonitor_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {
namespace plugins {

///
/// \brief The ARMFunctionMonitor class tracks call/return instruction pairs.
///
/// Clients use the onCall signal to be notified of call instructions and
/// optionally of return instructions in case they choose to register the corresponding
/// return signal. Call/return signals are paired and work for recursive functions too.
/// Note that compilers may introduce various optimizations (e.g., tail calls), which
/// may interfere with return signals.
///
/// This plugin only tracks modules in processes registered with ProcessExecutionDetector.
///
class ARMFunctionMonitor : public Plugin {
    S2E_PLUGIN

public:
    ARMFunctionMonitor(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    sigc::signal<void, S2EExecutionState *, uint32_t /* return pc */> onARMFunctionReturnEvent;

    sigc::signal<void, S2EExecutionState *, uint32_t /* caller PC */, uint64_t /* hash of callerpc and regs */>
        onARMFunctionCallEvent;

private:
    std::map<uint32_t, uint32_t> function_map;
    uint32_t function_parameter_num;
    uint32_t caller_level;

    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);
    void onFunctionCall(S2EExecutionState *state, uint64_t pc, unsigned source_type);
    void onFunctionReturn(S2EExecutionState *state, uint64_t pc);
    void onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc,
                             bool isStatic, uint64_t staticTarget);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_ARMFunctionMonitor_H
