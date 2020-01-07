///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_EXAMPLE_H
#define S2E_PLUGINS_EXAMPLE_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {
namespace plugins {

class Example : public Plugin {
    S2E_PLUGIN
public:
    Example(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    void slotTranslateBlockStart(ExecutionSignal *, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);

    void slotExecuteBlockStart(S2EExecutionState *state, uint64_t pc);

private:
    bool m_traceBlockTranslation;
    bool m_traceBlockExecution;
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_EXAMPLE_H
