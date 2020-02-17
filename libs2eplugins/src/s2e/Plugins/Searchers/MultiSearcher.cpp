///
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

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include "MultiSearcher.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(MultiSearcher, "MultiSearcher S2E plugin", "", );

void MultiSearcher::initialize() {
    s2e()->getCorePlugin()->onInitializationComplete.connect(sigc::mem_fun(*this, &MultiSearcher::onInitComplete));

    s2e()->getExecutor()->setSearcher(this);
}

void MultiSearcher::onInitComplete(S2EExecutionState *state) {
    if (m_searchers.empty()) {
        getWarningsStream() << "No searchers have been registered.\n";
        exit(-1);
    }
}

bool MultiSearcher::registerSearcher(const std::string &name, klee::Searcher *searcher) {
    if (m_searchers[name] == nullptr) {
        getDebugStream() << "Registering " << name << "\n";
        m_searchers[name] = searcher;

        if (m_searchers.size() == 1) {
            selectSearcher(name);
        }

        return true;
    }

    return false;
}

bool MultiSearcher::selectSearcher(const std::string &name) {
    Searchers::iterator it = m_searchers.find(name);
    if (it == m_searchers.end()) {
        return false;
    }

    if (m_currentSearcher != (*it).second) {
        getDebugStream() << "Switching to " << (*it).first << "\n";
    }

    m_currentSearcher = (*it).second;
    return true;
}

klee::ExecutionState &MultiSearcher::selectState() {
    assert(m_currentSearcher);
    return m_currentSearcher->selectState();
}

void MultiSearcher::update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                           const klee::StateSet &removedStates) {
    foreach2 (it, m_searchers.begin(), m_searchers.end()) { (*it).second->update(current, addedStates, removedStates); }
}

bool MultiSearcher::empty() {
    assert(m_currentSearcher);
    return m_currentSearcher->empty();
}

} // namespace plugins
} // namespace s2e
