///
/// Copyright (C) 2015-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_CUPASEARCHER_H
#define S2E_PLUGINS_CUPASEARCHER_H

#include <klee/Searcher.h>
#include <llvm/Support/TimeValue.h>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/ExecutionMonitors/FunctionMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/Plugins/Searchers/MultiSearcher.h>
#include <s2e/Plugins/StaticAnalysis/ControlFlowGraph.h>
#include <s2e/Plugins/Support/KeyValueStore.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Utils.h>

#include "Common.h"

#include <memory>
#include <random>
#include <unordered_map>

namespace s2e {
namespace plugins {

class DecreeMonitor;

///
/// \brief CUPASearcher implements the Class-Uniform Path Analysis (CUPA) algorithm.
///
/// This algorithm groups paths into equivalence classes.
///
/// Consider the following chain of equivalence classes:
///
/// ["pc", "pagedir", "random"]
/// - pc is a class that groups states by program counters at fork
/// - pagedir groups states by the value of their page directory register
/// - random creates one class per state and picks one class at random
///
/// Each group in a class is an independent searcher that manages its own
/// set of paths. In this example, the class "pc" would have groups composed
/// of class "pagedir", and so on recursively.
///
/// The cupa searcher requests a state from the top most
/// class (i.e., "pc"). That class selects a group according to its policy, then
/// recursively asks sub-classes to retrieve a state. The leaf class returns
/// the actual state. An intermediate class could also return a state, not
/// recursing down the chain.
///
/// Adding a state is done similarly to selecting a state. Eventually, searchers
/// form a tree, each level of the tree corresponding to one class.
///
/// Chains of classes are not commutative:
/// "pc", "pagedir", "random" is different from "pagedir", "pc", "random".
///
class CUPASearcher : public Plugin {
    S2E_PLUGIN
    friend class CUPASearcherReadCountClass;

public:
    CUPASearcher(S2E *s2e) : Plugin(s2e) {
    }
    void initialize();

    klee::Searcher *createSearcher(unsigned level);

    void updateState(S2EExecutionState *state);
    void update(klee::ExecutionState *current, const klee::StateSet &addedStates, const klee::StateSet &removedStates);

    void enable(bool e);

    uint64_t getBatchTime() const {
        return m_batchTime;
    }

private:
    enum Classes { SEED, BATCH, PC, PAGEDIR, FORKCOUNT, PRIORITY, READCOUNT, RANDOM, VULNERABILITY, GROUP };

    MultiSearcher *m_searchers;
    klee::Searcher *m_top;
    std::vector<Classes> m_classes;
    bool m_enabled;

    uint64_t m_batchTime;
};

class CUPASearcherClass : public klee::Searcher {
protected:
    CUPASearcher *m_plg;
    unsigned m_level;

    // Current CUPA class for each state
    std::unordered_map<klee::ExecutionState *, uint64_t> m_stateClasses;

    // Searchers for each CUPA class
    std::map<uint64_t, std::unique_ptr<klee::Searcher>> m_searchers;

    std::mt19937 m_rnd;

    void doAddState(klee::ExecutionState *state, uint64_t stateClass);
    void doRemoveState(klee::ExecutionState *state);

    llvm::raw_ostream &getDebugStream(S2EExecutionState *state = NULL) const;

protected:
    virtual uint64_t getClass(S2EExecutionState *state) = 0;

public:
    CUPASearcherClass(CUPASearcher *plugin, unsigned level) : m_plg(plugin), m_level(level){};

    virtual klee::ExecutionState &selectState();

    virtual void update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates);

    virtual bool empty();
};

/**************************************************************/
/**************************************************************/
/**************************************************************/

class CUPASearcherSeedClass : public CUPASearcherClass {
public:
    CUPASearcherSeedClass(CUPASearcher *plugin, unsigned level) : CUPASearcherClass(plugin, level){};

protected:
    virtual uint64_t getClass(S2EExecutionState *state) {
        if (!g_s2e_state) {
            return 0;
        }

        return state->getID() == 0 ? 0 : 1;
    }

    virtual klee::ExecutionState &selectState();
};

class CUPASearcherPcClass : public CUPASearcherClass {
public:
    CUPASearcherPcClass(CUPASearcher *plugin, unsigned level) : CUPASearcherClass(plugin, level){};

protected:
    virtual uint64_t getClass(S2EExecutionState *state) {
        if (!g_s2e_state)
            return 0;
        return state->getPc();
    }
};

class CUPASearcherPageDirClass : public CUPASearcherClass {
public:
    CUPASearcherPageDirClass(CUPASearcher *plugin, unsigned level) : CUPASearcherClass(plugin, level){};

protected:
    virtual uint64_t getClass(S2EExecutionState *state) {
        if (!g_s2e_state)
            return 0;
        return state->getPageDir();
    }
};

class CUPASearcherRandomClass : public CUPASearcherClass {
public:
    CUPASearcherRandomClass(CUPASearcher *plugin, unsigned level) : CUPASearcherClass(plugin, level){};

    virtual klee::ExecutionState &selectState();
    virtual void update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates);

    virtual bool empty() {
        return m_states.empty();
    }

private:
    typedef std::set<S2EExecutionState *> StateSet;
    StateSet m_states;

protected:
    virtual uint64_t getClass(S2EExecutionState *state) {
        if (!g_s2e_state)
            return 0;
        return std::uniform_int_distribution<>(0, m_states.size() - 1)(m_rnd);
    }
};

class CUPASearcherReadCountClass : public CUPASearcherClass {
public:
    CUPASearcherReadCountClass(CUPASearcher *plugin, unsigned level);
    virtual ~CUPASearcherReadCountClass() {
    }

    virtual klee::ExecutionState &selectState();

private:
    DecreeMonitor *m_monitor;

    static sigc::connection s_read_conn;

    static void onSymbolicRead(S2EExecutionState *state, uint64_t pid, uint64_t fd, uint64_t size,
                               const std::vector<std::pair<std::vector<klee::ref<klee::Expr>>, std::string>> &data,
                               klee::ref<klee::Expr> sizeExpr);

protected:
    virtual uint64_t getClass(S2EExecutionState *state);
};

typedef uint64_t distance_t;
#define DISTANCE_MAX UINT64_MAX

class CUPAVulnerabilitySearcherState : public PluginState {
private:
    std::vector<distance_t> m_distances;
    std::vector<uint64_t /* retPc */> m_retStack;

public:
    CUPAVulnerabilitySearcherState();
    virtual ~CUPAVulnerabilitySearcherState();

    virtual CUPAVulnerabilitySearcherState *clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    void setDistances(const std::vector<distance_t> &distances);
    const std::vector<distance_t> &getDistances() const;

    void pushRet(uint64_t retPc);
    void popRet();
    const std::vector<uint64_t> &getRetStack() const;
};

class CUPAVulnerabilitySearcherClass : public CUPASearcherClass {

private:
    typedef std::set<S2EExecutionState *> StateSet;

    typedef std::map<uint64_t /* startPc */, const ControlFlowGraph::BasicBlock *> BasicBlocksMap;
    typedef struct {
        BasicBlocksMap bbMap;
        std::vector<uint64_t> vulnPcs;

        // These fields keep cached analysis results
        std::map<uint64_t /* pc */, distance_t> retDist;
        std::map<std::pair<uint64_t /* pc */, uint64_t /* vulnPc */>, bool> canReachVuln;
        std::map<std::pair<uint64_t /* pc */, uint64_t /* vulnPc */>, distance_t> vulnDist;
    } Module;

    ControlFlowGraph *m_cfg;
    ModuleExecutionDetector *m_detector;
    FunctionMonitor *m_functionMonitor;

    int m_useParentSearcherProbability;

    StateSet m_states;

    std::map<std::string /* moduleName */, Module> m_modules;

    // These are recursive functions that traverse all BBs
    distance_t getRetDistance(Module &module, uint64_t pc, std::set<uint64_t> &visitedPcs); //
    bool canReachVulnerability(Module &module, uint64_t pc, uint64_t vulnPc, std::set<uint64_t> &visitedPcs);
    distance_t getVulnerabilityDistance(Module &module, uint64_t pc, uint64_t vulnPc, std::set<uint64_t> &visitedPcs);

    // These wrap recursive functions and cache their result
    distance_t getRetDistance(Module &module, uint64_t pc); //
    bool canReachVulnerability(Module &module, uint64_t pc, uint64_t vulnPc);
    distance_t getVulnerabilityDistance(Module &module, uint64_t pc, uint64_t vulnPc);

    // This takes call stack into account
    distance_t getVulnerabilityDistance(Module &module, uint64_t pc, uint64_t vulnPc,
                                        const std::vector<uint64_t> &retStack);

    void onTranslateInstruction(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);
    void onInstructionExecution(S2EExecutionState *state, uint64_t pc);

    void onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module);
    void onFunctionCall(S2EExecutionState *state, FunctionMonitorState *fns);

    void onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc, //
                             bool hasStaticTarget, uint64_t staticPc);
    void onReturnExecutionComplete(S2EExecutionState *state, uint64_t pc);

    void onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                const std::vector<klee::ref<klee::Expr>> &newConditions);

    sigc::connection translate_ins_conn;
    sigc::connection mod_load_conn;
    sigc::connection tb_end_conn;
    sigc::connection fork_conn;
    sigc::connection func_call_conn;

public:
    CUPAVulnerabilitySearcherClass(CUPASearcher *plugin, unsigned level);
    virtual ~CUPAVulnerabilitySearcherClass() {
        tb_end_conn.disconnect();
        translate_ins_conn.disconnect();
        mod_load_conn.disconnect();
        fork_conn.disconnect();
    }

    void initialize();

    virtual klee::ExecutionState &selectState();
    virtual void update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates);
    virtual bool empty();

protected:
    virtual uint64_t getClass(S2EExecutionState *state) {
        if (!g_s2e_state)
            return 0;

        DECLARE_PLUGINSTATE_P(m_plg, CUPAVulnerabilitySearcherState, state);
        distance_t sum = 0;
        std::vector<distance_t> dist = plgState->getDistances();
        for (unsigned i = 0; i < dist.size(); i++) {
            sum += dist[i];
        }

        return sum;
    }
};

///
/// \brief The CUPASearcherForkCountClass class splits states in two classes:
/// Those that forked more than x times at a given pc, and those that forked less.
/// If possible, prioritize states that forked less.
///
class CUPASearcherForkCountClass : public CUPASearcherClass {
private:
    typedef std::pair<uint64_t, uint64_t> pid_pc_t;
    typedef llvm::DenseMap<pid_pc_t, uint64_t> ForkCountMap;

    ForkCountMap m_map;

public:
    CUPASearcherForkCountClass(CUPASearcher *plugin, unsigned level) : CUPASearcherClass(plugin, level){};

protected:
    virtual uint64_t getClass(S2EExecutionState *state) {
        if (!g_s2e_state)
            return 0;

        auto p = std::make_pair(state->getPageDir(), state->getPc());
        uint64_t count = m_map[p];
        m_map[p] = count + 1;

        return count > 10 ? 1 : 0;
    }

    virtual klee::ExecutionState &selectState() {
        unsigned size = m_searchers.size();
        assert(size > 0 && size <= 2);
        (void) size;

        return std::begin(m_searchers)->second->selectState();
    }
};

class CUPASearcherPriorityClass : public CUPASearcherClass {
private:
    KeyValueStore *m_kvs;

public:
    CUPASearcherPriorityClass(CUPASearcher *plugin, unsigned level);

protected:
    virtual uint64_t getClass(S2EExecutionState *state);

    virtual klee::ExecutionState &selectState() {
        unsigned size = m_searchers.size();
        assert(size > 0);
        (void) size;

        return m_searchers.rbegin()->second->selectState();
    }
};

///
/// \brief Split states into groups of equal selection probability
///
/// Split states into groups by property 'group' from KeyValueStore.
/// A uniform distribution is used to select state from groups.
///
class CUPASearcherGroupClass : public CUPASearcherClass {
private:
    KeyValueStore *m_kvs;

public:
    CUPASearcherGroupClass(CUPASearcher *plugin, unsigned level);

protected:
    virtual uint64_t getClass(S2EExecutionState *state);
};

class CUPASearcherBatchClass : public CUPASearcherClass {
public:
    CUPASearcherBatchClass(CUPASearcher *plugin, unsigned level) : CUPASearcherClass(plugin, level) {
        m_state = NULL;
        m_lastSelectedTime = 0;
        m_batchTime = plugin->getBatchTime();
    }

private:
    klee::ExecutionState *m_state;
    uint64_t m_lastSelectedTime;
    uint64_t m_batchTime;

protected:
    virtual void update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates) {
        if (removedStates.count(m_state)) {
            m_state = NULL;
            m_lastSelectedTime = 0;
        }

        CUPASearcherClass::update(current, addedStates, removedStates);
    }

    virtual uint64_t getClass(S2EExecutionState *state) {
        return 0;
    }

    virtual klee::ExecutionState &selectState() {
        uint64_t curTime = llvm::sys::TimeValue::now().seconds();
        if (m_state) {
            if (curTime - m_lastSelectedTime < m_batchTime) {
                return *m_state;
            }
        }

        unsigned size = m_searchers.size();
        assert(size > 0);
        (void) size;
        m_state = &m_searchers.rbegin()->second->selectState();
        m_lastSelectedTime = curTime;
        return *m_state;
    }
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_CUPASEARCHER_H
