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

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <s2e/s2e_libcpu.h>

#include "EdgeCoverage.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(EdgeCoverage, "EdgeCoverage S2E plugin", "", "EdgeDetector", "ModuleExecutionDetector");

void EdgeCoverage::initialize() {
    m_edgeDetector = s2e()->getPlugin<EdgeDetector>();
    m_exec = s2e()->getPlugin<ModuleExecutionDetector>();

    s2e()->getCorePlugin()->onUpdateStates.connect(sigc::mem_fun(*this, &EdgeCoverage::onUpdateStates));

    m_edgeDetector->onEdge.connect(sigc::mem_fun(*this, &EdgeCoverage::onEdge));
}

void EdgeCoverage::onUpdateStates(S2EExecutionState *state, const klee::StateSet &addedStates,
                                  const klee::StateSet &removedStates) {
    foreach2 (it, removedStates.begin(), removedStates.end()) {
        S2EExecutionState *state = static_cast<S2EExecutionState *>(*it);
        // XXX: avoid the loop
        foreach2 (mit, m_nonCoveredEdges.begin(), m_nonCoveredEdges.end()) {
            MultiStatesEdges &bbs = (*mit).second;
            StatesByPointer &byptr = bbs.get<state_t>();
            byptr.erase(state);
        }
    }
}

void EdgeCoverage::onEdge(S2EExecutionState *state, uint64_t source, EdgeType type) {
    auto sm = m_exec->getModule(state, source);
    auto dm = m_exec->getModule(state, state->regs()->getPc());
    if (sm != dm) {
        return;
    }

    bool ok = true;
    uint64_t s, d;

    ok &= sm->ToNativeBase(source, s);
    ok &= sm->ToNativeBase(state->regs()->getPc(), d);

    if (!ok) {
        getWarningsStream(state) << "Could not get source/destination address for edge\n";
        return;
    }

    Edge e = std::make_pair(s, d);

    StateLocations::iterator cit = m_nonCoveredEdges.find(sm->Name);
    if (cit == m_nonCoveredEdges.end()) {
        return;
    }

    MultiStatesEdges &edges = (*cit).second;
    StatesByEdge &bye = edges.get<edge_t>();

    bool found = false;
    while (bye.find(e) != bye.end()) {
        bye.erase(e);
        found = true;
    }

    if (found) {
        getDebugStream(state) << "Covered edge " << hexval(e.first) << " " << hexval(e.second) << "\n";
        m_coveredEdges[sm->Name].insert(e);
    }
}

void EdgeCoverage::addNonCoveredEdge(S2EExecutionState *state, const std::string &module, uint64_t source,
                                     uint64_t dest) {
    if (isCovered(module, source, dest)) {
        return;
    }

    StateEdge info;
    info.state = state;
    info.edge = std::make_pair(source, dest);
    m_nonCoveredEdges[module].insert(info);

    getDebugStream(state) << "Adding non-covered edge " << hexval(info.edge.first) << " " << hexval(info.edge.second)
                          << "\n";

    EdgeType type;
    if (!m_edgeDetector->findEdge(module, source, dest, &type)) {
        m_edgeDetector->addEdge(module, source, dest, EDGE_NONE);
        se_tb_safe_flush();
    }
}

S2EExecutionState *EdgeCoverage::getNonCoveredState(llvm::DenseSet<S2EExecutionState *> &filter) {
    foreach2 (it, m_nonCoveredEdges.begin(), m_nonCoveredEdges.end()) {
        MultiStatesEdges &bbs = (*it).second;
        StatesByEdge &bypc = bbs.get<edge_t>();

        foreach2 (bit, bypc.begin(), bypc.end()) {
            S2EExecutionState *state = (*bit).state;
            if (filter.find(state) != filter.end()) {
                getDebugStream() << "State id " << (*bit).state->getID() << " has not covered edge "
                                 << hexval((*bit).edge.first) << ", " << hexval((*bit).edge.second) << " yet\n";
                return (*bit).state;
            }
        }
    }

    return nullptr;
}

} // namespace plugins
} // namespace s2e
