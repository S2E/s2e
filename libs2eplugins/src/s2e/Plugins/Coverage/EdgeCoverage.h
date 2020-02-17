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

#ifndef S2E_PLUGINS_EdgeCoverage_H
#define S2E_PLUGINS_EdgeCoverage_H

#include <llvm/ADT/DenseSet.h>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/Plugins/StaticAnalysis/EdgeDetector.h>
#include <s2e/S2EExecutionState.h>

#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index_container.hpp>

namespace s2e {
namespace plugins {

class EdgeCoverage : public Plugin {
    S2E_PLUGIN
private:
    typedef std::pair<uint64_t, uint64_t> Edge;
    struct StateEdge {
        S2EExecutionState *state;
        Edge edge;
    };

    struct state_t {};
    struct edge_t {};

    typedef boost::multi_index_container<
        StateEdge,
        boost::multi_index::indexed_by<
            boost::multi_index::ordered_unique<boost::multi_index::tag<state_t>,
                                               BOOST_MULTI_INDEX_MEMBER(StateEdge, S2EExecutionState *, state)>,
            boost::multi_index::ordered_non_unique<boost::multi_index::tag<edge_t>,
                                                   BOOST_MULTI_INDEX_MEMBER(StateEdge, Edge, edge)>>>
        MultiStatesEdges;

    typedef MultiStatesEdges::index<state_t>::type StatesByPointer;
    typedef MultiStatesEdges::index<edge_t>::type StatesByEdge;
    typedef std::map<std::string, MultiStatesEdges> StateLocations;

    typedef llvm::DenseSet<Edge> CoveredEdges;
    typedef std::map<std::string, CoveredEdges> Coverage;

    Coverage m_coveredEdges;
    StateLocations m_nonCoveredEdges;

public:
    EdgeCoverage(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    bool isCovered(const std::string &module, uint64_t source, uint64_t dest) {
        Coverage::iterator mit = m_coveredEdges.find(module);
        if (mit == m_coveredEdges.end()) {
            return false;
        }

        Edge edge = std::make_pair(source, dest);
        return (*mit).second.find(edge) != (*mit).second.end();
    }

    void addNonCoveredEdge(S2EExecutionState *state, const std::string &module, uint64_t source, uint64_t dest);
    S2EExecutionState *getNonCoveredState(llvm::DenseSet<S2EExecutionState *> &filter);

private:
    EdgeDetector *m_edgeDetector;
    ModuleExecutionDetector *m_exec;

    void onUpdateStates(S2EExecutionState *state, const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates);

    void onEdge(S2EExecutionState *state, uint64_t source, EdgeType type);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_EdgeCoverage_H
