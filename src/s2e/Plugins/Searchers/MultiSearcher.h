///
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_MultiSearcher_H
#define S2E_PLUGINS_MultiSearcher_H

#include <klee/Searcher.h>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>

#include <map>

namespace s2e {
namespace plugins {

class MultiSearcher : public Plugin, public klee::Searcher {
    S2E_PLUGIN

private:
    typedef std::map<std::string, klee::Searcher *> Searchers;

    Searchers m_searchers;
    klee::Searcher *m_currentSearcher;

    void onInitComplete(S2EExecutionState *state);

public:
    MultiSearcher(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    bool registerSearcher(const std::string &name, klee::Searcher *searcher);
    bool selectSearcher(const std::string &name);

    virtual klee::ExecutionState &selectState();

    virtual void update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates);

    virtual bool empty();

private:
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_MultiSearcher_H
