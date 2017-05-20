///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_BSOD_H
#define S2E_PLUGINS_BSOD_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/S2EExecutionState.h>
#include <vmi/WindowsCrashDumpGenerator.h>
#include "WindowsMonitor.h"

namespace s2e {
namespace plugins {

struct S2E_BSOD_COMMAND {
    uint64_t Code;
    uint64_t Parameters[4];
    uint64_t Header;
    uint64_t HeaderSize;
};

class BlueScreenInterceptor : public Plugin, public BaseInstructionsPluginInvokerInterface {
    S2E_PLUGIN
public:
    BlueScreenInterceptor(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    /* Other plugins can react to kernel crashes via this signal */
    sigc::signal<void, S2EExecutionState *, /* currentState */
                 vmi::windows::BugCheckDescription *>
        onBlueScreen;

    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);

private:
    WindowsMonitor *m_monitor;

    bool invokeCrashRoutine(S2EExecutionState *state, uint64_t pc);

    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);

    void onBsod(S2EExecutionState *state, uint64_t pc);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_EXAMPLE_H
