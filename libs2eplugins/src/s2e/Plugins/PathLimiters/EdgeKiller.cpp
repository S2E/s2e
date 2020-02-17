///
/// Copyright (C) 2011-2015, Dependable Systems Laboratory, EPFL
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
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include <iostream>

#include "EdgeKiller.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(EdgeKiller, "Kills states that encounter a given (start_pc, end_pc) edge", "", "EdgeDetector",
                  "ModuleExecutionDetector");

void EdgeKiller::initialize() {
    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();
    m_edgeDetector = s2e()->getPlugin<EdgeDetector>();
    m_edgeDetector->readConfig(getConfigKey(), this);
    m_edgeDetector->onEdge.connect(sigc::mem_fun(*this, &EdgeKiller::onEdge));
}

void EdgeKiller::addEdge(const std::string &moduleName, uint64_t start, uint64_t end, EdgeType type) {
    getDebugStream() << "EdgeKiller: adding edge " << moduleName << " " << hexval(start) << " => " << hexval(end)
                     << " type:" << type << "\n";
    m_edgeDetector->addEdge(moduleName, start, end, type);
    m_edges.addEdge(moduleName, start, end, type);
}

void EdgeKiller::onEdge(S2EExecutionState *state, uint64_t sourcePc, EdgeType type) {
    auto md = m_detector->getCurrentDescriptor(state);
    if (!md) {
        return;
    }

    uint64_t relSourcePc, relPc;
    bool ok = true;
    ok &= md->ToNativeBase(sourcePc, relSourcePc);
    ok &= md->ToNativeBase(state->regs()->getPc(), relPc);
    if (!ok) {
        getWarningsStream(state) << "Could not get relative source/dest address\n";
        return;
    }

    if (!m_edges.findEdge(md->Name, relSourcePc, relPc, &type)) {
        return;
    }

    std::string s;
    llvm::raw_string_ostream ss(s);
    ss << "EdgeKiller: " << hexval(sourcePc) << " => " << hexval(state->regs()->getPc()) << "\n";
    ss.flush();
    s2e()->getExecutor()->terminateState(*state, s);
}

} // namespace plugins
} // namespace s2e
