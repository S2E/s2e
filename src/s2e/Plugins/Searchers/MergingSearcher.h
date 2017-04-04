///
/// Copyright (C) 2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_MERGINGSEARCHER_H
#define S2E_PLUGINS_MERGINGSEARCHER_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/S2EExecutionState.h>

#include <llvm/ADT/DenseSet.h>

#include <klee/Searcher.h>

namespace s2e {
namespace plugins {

class IMergingSearcher {
public:
    virtual ~IMergingSearcher() {
    }
    virtual S2EExecutionState *selectState() = 0;
    virtual void update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates) = 0;

    virtual void setActive(S2EExecutionState *state, bool active) = 0;
};

class MergingSearcher : public Plugin, public klee::Searcher, public BaseInstructionsPluginInvokerInterface {
    S2E_PLUGIN

public:
    typedef llvm::DenseSet<S2EExecutionState *> States;

private:
    /* Custom instruction command */
    struct merge_desc_t {
        uint64_t start;
    };

    struct merge_pool_t {
        /* First state that got to the merge_end instruction */
        S2EExecutionState *firstState;

        /* All the states that belong to the pool */
        States states;

        merge_pool_t() {
            firstState = NULL;
        }
    };

    /* maps a group id to the first state */
    typedef std::map<uint64_t, merge_pool_t> MergePools;

    MergePools m_mergePools;
    States m_activeStates;
    S2EExecutionState *m_currentState;
    uint64_t m_nextMergeGroupId;

    IMergingSearcher *m_selector;

    bool m_debug;

public:
    MergingSearcher(S2E *s2e) : Plugin(s2e) {
    }
    void initialize();

    void setCustomSelector(IMergingSearcher *selector) {
        m_selector = selector;
    }

    States &getActiveStates() {
        return m_activeStates;
    }

    virtual klee::ExecutionState &selectState();

    virtual void update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates);

    virtual bool empty();

    bool mergeStart(S2EExecutionState *state);
    bool mergeEnd(S2EExecutionState *state, bool skipOpcode, bool clearTmpFlags);

private:
    void suspend(S2EExecutionState *state);
    void resume(S2EExecutionState *state);

    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);
};

class MergingSearcherState : public PluginState {
private:
    uint64_t m_groupId;

public:
    MergingSearcherState();
    virtual ~MergingSearcherState();
    virtual MergingSearcherState *clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    void setGroupId(uint64_t groupId) {
        m_groupId = groupId;
    }

    uint64_t getGroupId() const {
        return m_groupId;
    }
};

} // namespace plugins
} // namespace s2e

#endif
