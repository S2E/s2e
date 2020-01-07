///
/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include "Example.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(Example, "Example S2E plugin", "", );

void Example::initialize() {
    m_traceBlockTranslation = s2e()->getConfig()->getBool(getConfigKey() + ".traceBlockTranslation");

    m_traceBlockExecution = s2e()->getConfig()->getBool(getConfigKey() + ".traceBlockExecution");

    s2e()->getCorePlugin()->onTranslateBlockStart.connect(sigc::mem_fun(*this, &Example::slotTranslateBlockStart));
}

void Example::slotTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                      uint64_t pc) {
    if (m_traceBlockTranslation) {
        getDebugStream(state) << "Translating block at " << hexval(pc) << "\n";
    }

    if (m_traceBlockExecution) {
        signal->connect(sigc::mem_fun(*this, &Example::slotExecuteBlockStart));
    }
}

void Example::slotExecuteBlockStart(S2EExecutionState *state, uint64_t pc) {
    getDebugStream(state) << "Executing block at " << hexval(pc) << "\n";
}

} // namespace plugins
} // namespace s2e
