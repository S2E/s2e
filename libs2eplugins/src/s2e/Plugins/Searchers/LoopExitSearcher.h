///
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

#ifndef S2E_PLUGINS_LoopExitSearcher_H
#define S2E_PLUGINS_LoopExitSearcher_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/Coverage/BasicBlockCoverage.h>
#include <s2e/Plugins/Coverage/EdgeCoverage.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/Plugins/StaticAnalysis/ControlFlowGraph.h>
#include <s2e/Plugins/StaticAnalysis/EdgeDetector.h>
#include <s2e/Plugins/StaticAnalysis/LoopDetector.h>
#include <s2e/S2EExecutionState.h>

#include <klee/Searcher.h>

#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index_container.hpp>

#include "Common.h"

namespace s2e {
namespace plugins {

class LoopExitSearcher : public Plugin, public klee::Searcher {
    S2E_PLUGIN

private:
    typedef llvm::DenseMap<uint64_t, uint64_t> ForkCounts;
    typedef std::map<std::string, ForkCounts> ModuleForkCounts;

    ModuleForkCounts m_forkCount;

    LoopDetector *m_loopDetector;
    ControlFlowGraph *m_cfg;
    ModuleExecutionDetector *m_detector;
    coverage::BasicBlockCoverage *m_bbcov;
    EdgeCoverage *m_ecov;

    searchers::MultiStates m_states;
    searchers::MultiStates m_waitingStates;
    S2EExecutionState *m_currentState;

    unsigned m_timerTicks;

    void onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                const std::vector<klee::ref<klee::Expr>> &newConditions);

    void onTimer();

    void increasePriority(S2EExecutionState *state, int64_t p);

public:
    LoopExitSearcher(S2E *s2e) : Plugin(s2e) {
    }
    void initialize();

    virtual klee::ExecutionState &selectState();

    virtual void update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates);

    virtual bool empty();

private:
};

} // namespace plugins
} // namespace s2e

#endif
