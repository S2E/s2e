///
/// Copyright (C) 2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_PATHSEARCHER_H_
#define S2E_PLUGINS_PATHSEARCHER_H_

#include <klee/Searcher.h>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {
namespace plugins {

class PathSearcher : public Plugin, public klee::Searcher {
    S2E_PLUGIN

private:
    typedef std::set<S2EExecutionState *> StateSet;

    StateSet m_states;
    S2EExecutionState *m_chosenState;

    uint64_t m_vulnPc;

    typedef struct {
        uint64_t pc;
        int id;
    } forkDirector;

    std::vector<forkDirector> m_forkDirectors;

    void onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                const std::vector<klee::ref<klee::Expr>> &newConditions);

    void onTranslateInstruction(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);
    void onInstructionExecution(S2EExecutionState *state, uint64_t pc);
    void onSegFault(S2EExecutionState *state, uint64_t pid, uint64_t pc);

public:
    PathSearcher(S2E *s2e);

    void initialize();

    virtual klee::ExecutionState &selectState();
    virtual void update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates);
    virtual bool empty();
};

class PathSearcherState : public PluginState {
private:
    unsigned m_forkCount;

public:
    PathSearcherState();
    virtual ~PathSearcherState();

    virtual PathSearcherState *clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    void increaseForkCount();
    unsigned getForkCount() const;
};

} // namespace plugins
} // namespace s2e

#endif /* S2E_PLUGINS_PATHSEARCHER_H_ */
