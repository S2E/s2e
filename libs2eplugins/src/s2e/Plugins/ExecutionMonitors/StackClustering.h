///
/// Copyright (C) 2013-2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
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

#ifndef S2E_PLUGINS_StackClustering_H
#define S2E_PLUGINS_StackClustering_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

#include <s2e/Plugins/ExecutionMonitors/StackMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/Plugins/StaticAnalysis/ControlFlowGraph.h>

#include "CallTree.h"

namespace s2e {
namespace plugins {

class OSMonitor;

class StackClustering : public Plugin {
    S2E_PLUGIN
public:
    StackClustering(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

private:
    typedef calltree::CallTree<S2EExecutionState *> StateCallTree;

    StackMonitor *m_stackMonitor;
    ModuleExecutionDetector *m_detector;
    ControlFlowGraph *m_cfg;
    StateCallTree m_callTree;
    OSMonitor *m_monitor;

    unsigned m_timer;
    unsigned m_interval;

    void computeCallStack(S2EExecutionState *originalState, calltree::CallStack &cs, calltree::Location &loc);

    void onStateFork(S2EExecutionState *originalState, const std::vector<S2EExecutionState *> &newStates,
                     const std::vector<klee::ref<klee::Expr>> &newConditions);

    void onTimer();

    void onUpdateStates(S2EExecutionState *state, const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates);

public:
    StateCallTree &getCallTree() {
        return m_callTree;
    }

    void add(S2EExecutionState *state);

    void print();
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_StackClustering_H
