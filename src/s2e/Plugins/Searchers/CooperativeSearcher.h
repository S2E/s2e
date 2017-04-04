///
/// Copyright (C) 2011-2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_COOPSEARCHER_H
#define S2E_PLUGINS_COOPSEARCHER_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/S2EExecutionState.h>

#include <klee/Searcher.h>

#include <vector>

namespace s2e {
namespace plugins {

#define COOPSEARCHER_OPCODE 0xAB

class CooperativeSearcher : public Plugin, public klee::Searcher {
    S2E_PLUGIN
public:
    enum CoopSchedulerOpcodes {
        ScheduleNext = 0,
        Yield = 1,
    };

    typedef std::map<uint32_t, S2EExecutionState *> States;

    CooperativeSearcher(S2E *s2e) : Plugin(s2e) {
    }
    void initialize();

    // Selects the last specified state.
    // If no states specified, schedules the one with the lowest ID.
    virtual klee::ExecutionState &selectState();

    virtual void update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates);

    virtual bool empty();

private:
    bool m_searcherInited;
    States m_states;
    S2EExecutionState *m_currentState;

    void initializeSearcher();

    void onCustomInstruction(S2EExecutionState *state, uint64_t opcode);
};

} // namespace plugins
} // namespace s2e

#endif
