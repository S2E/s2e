///
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
    if (m_searchers[name] == NULL) {
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
