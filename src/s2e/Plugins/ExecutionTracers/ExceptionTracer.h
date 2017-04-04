///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_ExceptionTracer_H
#define S2E_PLUGINS_ExceptionTracer_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>
#include "ExecutionTracer.h"

namespace s2e {
namespace plugins {

class ExceptionTracer : public Plugin {
    S2E_PLUGIN
public:
    ExceptionTracer(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

private:
    ExecutionTracer *m_tracer;

    void onException(S2EExecutionState *state, unsigned vec, uint64_t pc);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_ExceptionTracer_H
