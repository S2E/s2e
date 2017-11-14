///
/// Copyright (C) 2015-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/cpu.h>

#include <cxxabi.h>

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/Linux/DecreeMonitor.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>

#include <klee/UserSearcher.h>

#include <algorithm>
#include <random>

#include "CUPASearcher.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(CUPASearcher, "CUPA searcher", "", "ModuleExecutionDetector", "MultiSearcher");

///
/// \brief Initializes the CUPA Searcher plugin
///
/// Implementation notes
///
/// - Do not use onStateFork event to update states. Only use the standard
///   searcher API (selectState, update). onStateFork is hard to get
///   right and may result in corruption of the searcher state. The symptom
///   is the searcher returning a state that was already killed.
///
///   It is not totally clear why at this moment, so if the problem reappears
///   here are a few hypothesis that were checked:
///
///   1. An execution state might end up in multiple different searcher classes,
///   because getClass() may not be deterministic. In other words, calling
///   it once in onFork, then in updateState might lead to inserting the same
///   state into multiple classes. Later, if the state is deleted, it will only
///   be deleted from one class, potentially leading to selectNextState()
///   returning a stale state pointer that could have already been freed.
///   (XXX: adding doRemove in update() doesn't fix it)
///
///   2. Some plugin in onFork could throw an exception, preventing the CUPA
///   searcher from updating the state properly.
///
void CUPASearcher::initialize() {
    m_searchers = s2e()->getPlugin<MultiSearcher>();

    ConfigFile *cfg = s2e()->getConfig();

    m_batchTime = cfg->getInt(getConfigKey() + ".batchTime", 5);

    ConfigFile::string_list classes = cfg->getStringList(getConfigKey() + ".classes");

    if (classes.empty()) {
        getWarningsStream() << "Please specify one or more searcher classes\n";
        exit(-1);
    }

    foreach2 (it, classes.begin(), classes.end()) {
        if (*it == "seed") {
            m_classes.push_back(SEED);
        } else if (*it == "batch") {
            m_classes.push_back(BATCH);
        } else if (*it == "pc") {
            m_classes.push_back(PC);
        } else if (*it == "pagedir") {
            m_classes.push_back(PAGEDIR);
        } else if (*it == "forkcount") {
            m_classes.push_back(FORKCOUNT);
        } else if (*it == "priority") {
            m_classes.push_back(PRIORITY);
        } else if (*it == "readcount") {
            m_classes.push_back(READCOUNT);
        } else if (*it == "random") {
            m_classes.push_back(RANDOM);
        } else if (*it == "vulnerability") {
            m_classes.push_back(VULNERABILITY);
        } else if (*it == "group") {
            m_classes.push_back(GROUP);
        } else {
            getWarningsStream() << "Unknown class " << *it;
            exit(-1);
        }
    }

    m_top = createSearcher(0);

    m_searchers->registerSearcher("CUPASearcher", m_top);

    bool ok;
    m_enabled = cfg->getBool(getConfigKey() + ".enabled", true, &ok);
    if (ok && !m_enabled) {
        getInfoStream() << "CUPASearcher is in disabled mode\n";
    } else {
        enable(true);
    }
}

void CUPASearcher::enable(bool e) {
    m_enabled = e;
    if (e) {
        m_searchers->selectSearcher("CUPASearcher");
        getInfoStream() << "CUPASearcher is now active\n";
    } else {
        getInfoStream() << "CUPASearcher is now disabled\n";
    }
}

klee::Searcher *CUPASearcher::createSearcher(unsigned level) {
    assert(level <= m_classes.size());
    klee::Searcher *searcher;

    if (level < m_classes.size()) {
        switch (m_classes[level]) {
            case SEED:
                searcher = new CUPASearcherSeedClass(this, level);
                break;
            case BATCH:
                searcher = new CUPASearcherBatchClass(this, level);
                break;
            case PC:
                searcher = new CUPASearcherPcClass(this, level);
                break;
            case PAGEDIR:
                searcher = new CUPASearcherPageDirClass(this, level);
                break;
            case FORKCOUNT:
                searcher = new CUPASearcherForkCountClass(this, level);
                break;
            case PRIORITY:
                searcher = new CUPASearcherPriorityClass(this, level);
                break;
            case READCOUNT:
                searcher = new CUPASearcherReadCountClass(this, level);
                break;
            case RANDOM:
                searcher = new CUPASearcherRandomClass(this, level);
                break;
            case VULNERABILITY:
                searcher = new CUPAVulnerabilitySearcherClass(this, level);
                break;
            case GROUP:
                searcher = new CUPASearcherGroupClass(this, level);
                break;
            default:
                assert(false);
        }
    } else {
        searcher = klee::constructUserSearcher(*g_s2e->getExecutor());
    }

    return searcher;
}

void CUPASearcher::updateState(S2EExecutionState *state) {
    m_top->removeState(state);
    m_top->addState(state);
}

void CUPASearcher::update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                          const klee::StateSet &removedStates) {
    m_top->update(current, addedStates, removedStates);
}

/**************************************************************/
/**************************************************************/
/**************************************************************/

llvm::raw_ostream &CUPASearcherClass::getDebugStream(S2EExecutionState *state) const {
    if (m_plg->getLogLevel() <= LOG_DEBUG) {
        // TODO: find a way to move this to plugin class.
        int status;
        std::string name = typeid(*this).name();
        char *demangled = abi::__cxa_demangle(name.c_str(), 0, 0, &status);
        llvm::raw_ostream &ret = m_plg->getDebugStream(state) << demangled << "(" << hexval(this) << ") - ";
        free(demangled);
        return ret;
    } else {
        return m_plg->getNullStream();
    }
}

void CUPASearcherClass::doAddState(klee::ExecutionState *state, uint64_t stateClass) {
    auto searchersIt = m_searchers.find(stateClass);
    if (searchersIt == m_searchers.end()) {
        getDebugStream() << "Creating new searcher for class " << hexval(stateClass) << "\n";
        klee::Searcher *searcher = m_plg->createSearcher(m_level + 1);
        searchersIt = m_searchers.emplace(stateClass, std::unique_ptr<klee::Searcher>(searcher)).first;
    }

    assert(m_stateClasses.find(state) == m_stateClasses.end());
    m_stateClasses[state] = stateClass;
    searchersIt->second->addState(state);
}

void CUPASearcherClass::doRemoveState(klee::ExecutionState *state) {
    auto stateClassesIt = m_stateClasses.find(state);
    if (stateClassesIt == m_stateClasses.end()) {
        return;
    }

    uint64_t stateClass = stateClassesIt->second;
    m_stateClasses.erase(stateClassesIt);

    // Remove state from the searcher
    auto searchersIt = m_searchers.find(stateClass);
    assert(searchersIt != m_searchers.end());
    searchersIt->second->removeState(state);

    if (searchersIt->second->empty()) {
        getDebugStream() << " class " << hexval(stateClass) << " is empty, deleting its searcher\n";
        m_searchers.erase(searchersIt);
    }
}

void CUPASearcherClass::update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                               const klee::StateSet &removedStates) {

    for (auto addedState : addedStates) {
        if (m_stateClasses.count(addedState) == 0) {
            S2EExecutionState *s = static_cast<S2EExecutionState *>(addedState);
            // XXX: removing state here first before re-adding
            // does not solve the problem caused by fork
            // (see implementation notes)
            doAddState(addedState, getClass(s));
        }
    }

    for (auto removedState : removedStates) {
        doRemoveState(removedState);
    }
}

klee::ExecutionState &CUPASearcherClass::selectState() {
    assert(!m_searchers.empty());
    int idx = std::uniform_int_distribution<>(0, m_searchers.size() - 1)(m_rnd);
    getDebugStream(NULL) << "selectState class " << idx << "\n";
    return std::next(std::begin(m_searchers), idx)->second->selectState();
}

bool CUPASearcherClass::empty() {
    return m_searchers.empty();
}

/**************************************************************/
/**************************************************************/
/**************************************************************/

struct PriorityClass {
    CUPASearcher *cupa;
    sigc::connection s_priority_connection;

    void onLocalPut(S2EExecutionState *state, const std::string &key, const std::string &value, bool success) {
        if (!success || key != "priority") {
            return;
        }

        cupa->getDebugStream(state) << "Updating priority\n";

        cupa->updateState(state);
    }
};

static PriorityClass s_pc;

CUPASearcherPriorityClass::CUPASearcherPriorityClass(CUPASearcher *plugin, unsigned level)
    : CUPASearcherClass(plugin, level) {
    m_kvs = plugin->s2e()->getPlugin<KeyValueStore>();
    if (!m_kvs) {
        plugin->getDebugStream() << "KeyValueStore plugin must be enabled for the CUPASearcherPriorityClass\n";
        exit(-1);
    }

    if (!s_pc.s_priority_connection.connected()) {
        s_pc.cupa = plugin;
        s_pc.s_priority_connection = m_kvs->onLocalPut.connect(sigc::mem_fun(s_pc, &PriorityClass::onLocalPut));
    }
}

uint64_t CUPASearcherPriorityClass::getClass(S2EExecutionState *state) {
    std::string value;
    if (!m_kvs->get(state, "priority", value)) {
        return 0;
    }

    uint64_t p = strtol(value.c_str(), NULL, 0);
    getDebugStream(state) << "CUPASearcherPriorityClass priority " << p << "\n";
    return p;
}

struct GroupClass {
    CUPASearcher *cupa;
    sigc::connection s_group_connection;

    void onLocalPut(S2EExecutionState *state, const std::string &key, const std::string &value, bool success) {
        if (!success || key != "group") {
            return;
        }

        cupa->getDebugStream(state) << "Updating group\n";

        cupa->updateState(state);
    }
};

static GroupClass s_gc;

CUPASearcherGroupClass::CUPASearcherGroupClass(CUPASearcher *plugin, unsigned level)
    : CUPASearcherClass(plugin, level) {
    m_kvs = plugin->s2e()->getPlugin<KeyValueStore>();
    if (!m_kvs) {
        plugin->getDebugStream() << "KeyValueStore plugin must be enabled for the CUPASearcherGroupClass\n";
        exit(-1);
    }

    if (!s_gc.s_group_connection.connected()) {
        s_gc.cupa = plugin;
        s_gc.s_group_connection = m_kvs->onLocalPut.connect(sigc::mem_fun(s_gc, &GroupClass::onLocalPut));
    }
}

uint64_t CUPASearcherGroupClass::getClass(S2EExecutionState *state) {
    std::string value;
    if (!m_kvs->get(state, "group", value)) {
        return 0;
    }

    uint64_t group = strtoull(value.c_str(), NULL, 0);
    getDebugStream(state) << "CUPASearcherGroupClass group " << group << "\n";
    return group;
}

klee::ExecutionState &CUPASearcherRandomClass::selectState() {
    if (m_states.size() > 0) {
        int idx = std::uniform_int_distribution<>(0, m_states.size() - 1)(m_rnd);
        S2EExecutionState *es = dynamic_cast<S2EExecutionState *>(*std::next(std::begin(m_states), idx));
        getDebugStream(es) << hexval(this) << " selected state " << es->getID() << "\n";
        return *es;
    }
    return CUPASearcherClass::selectState();
}

klee::ExecutionState &CUPASearcherSeedClass::selectState() {
    /**
     * Never schedule the unique state in the seed class,
     *  unless it's the only state.
     */
    auto it = m_searchers.find(1);
    if (it == m_searchers.end()) {
        return CUPASearcherClass::selectState();
    }

    return (*it).second->selectState();
}

void CUPASearcherRandomClass::update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                                     const klee::StateSet &removedStates) {
    foreach2 (it, addedStates.begin(), addedStates.end()) {
        S2EExecutionState *es = dynamic_cast<S2EExecutionState *>(*it);
        m_states.insert(es);
    }

    foreach2 (it, removedStates.begin(), removedStates.end()) {
        S2EExecutionState *es = dynamic_cast<S2EExecutionState *>(*it);
        m_states.erase(es);
    }
}

sigc::connection CUPASearcherReadCountClass::s_read_conn;

CUPASearcherReadCountClass::CUPASearcherReadCountClass(CUPASearcher *plugin, unsigned level)
    : CUPASearcherClass(plugin, level) {
    m_monitor = plugin->s2e()->getPlugin<DecreeMonitor>();

    if (!s_read_conn.connected()) {
        s_read_conn = m_monitor->onSymbolicRead.connect(sigc::ptr_fun(&CUPASearcherReadCountClass::onSymbolicRead));
    }

    getDebugStream() << "Searcher created\n";
}

/**
 * This has to be a static function because we don't know in which bucket the class is.
 * Also, updating the class would require updating all the downstream cupa classes.
 * Need to ask the cupa searcher to reconstruct the chain.
 */
void CUPASearcherReadCountClass::onSymbolicRead(
    S2EExecutionState *state, uint64_t pid, uint64_t fd, uint64_t size,
    const std::vector<std::pair<std::vector<klee::ref<klee::Expr>>, std::string>> &data,
    klee::ref<klee::Expr> sizeExpr) {
    CUPASearcher *searcher = g_s2e->getPlugin<CUPASearcher>();
    searcher->updateState(state);
}

/**
 * Selects the class with the fewest number of reads first.
 */
klee::ExecutionState &CUPASearcherReadCountClass::selectState() {
    assert(!m_searchers.empty());
    return (*m_searchers.begin()).second->selectState();
}

uint64_t CUPASearcherReadCountClass::getClass(S2EExecutionState *state) {
    if (!g_s2e_state) {
        return 0;
    }

    return m_monitor->getSymbolicReadsCount(state);
}

CUPAVulnerabilitySearcherClass::CUPAVulnerabilitySearcherClass(CUPASearcher *plugin, unsigned level)
    : CUPASearcherClass(plugin, level) {
    m_cfg = NULL;
    m_detector = NULL;
    m_functionMonitor = NULL;
    m_useParentSearcherProbability = 0;
    initialize();
}

void CUPAVulnerabilitySearcherClass::initialize() {
    m_cfg = m_plg->s2e()->getPlugin<ControlFlowGraph>();
    m_detector = m_plg->s2e()->getPlugin<ModuleExecutionDetector>();
    m_functionMonitor = m_plg->s2e()->getPlugin<FunctionMonitor>();
    CorePlugin *core = m_plg->s2e()->getCorePlugin();

    if (!m_cfg || !m_detector || !m_functionMonitor) {
        m_plg->getWarningsStream() << "Please enable FunctionMonitor, ModuleExecutionDetector, and ControlFlowGraph "
                                      "plugins to use the vulnerability class\n";
        exit(-1);
    }

    translate_ins_conn = core->onTranslateInstructionStart.connect(
        sigc::mem_fun(*this, &CUPAVulnerabilitySearcherClass::onTranslateInstruction));
    mod_load_conn =
        m_detector->onModuleLoad.connect(sigc::mem_fun(*this, &CUPAVulnerabilitySearcherClass::onModuleLoad));
    tb_end_conn =
        core->onTranslateBlockEnd.connect(sigc::mem_fun(*this, &CUPAVulnerabilitySearcherClass::onTranslateBlockEnd));
    fork_conn = core->onStateFork.connect_front(sigc::mem_fun(*this, &CUPAVulnerabilitySearcherClass::onFork));

    ConfigFile *config = m_plg->s2e()->getConfig();

    m_useParentSearcherProbability =
        config->getInt(m_plg->getConfigKey() + ".vulnerability.useParentSearcherProbability", 0);
    if (m_useParentSearcherProbability < 0 || m_useParentSearcherProbability > 100) {
        m_plg->getWarningsStream() << "invalid probability value\n";
        exit(-1);
    }

    ConfigFile::string_list keys = config->getListKeys(m_plg->getConfigKey() + ".vulnerability.modules");
    foreach2 (it, keys.begin(), keys.end()) {
        const std::string &keyName = *it;

        ModuleExecutionCfg moduleConfig;
        if (!m_detector->getModuleConfig(keyName, moduleConfig)) {
            m_plg->getWarningsStream() << "module id " << keyName << " is not availble in ModuleExecutionDetector\n";
            exit(-1);
        }

        Module &module = m_modules[moduleConfig.moduleName];

        std::stringstream ss0;
        ss0 << m_plg->getConfigKey() << ".vulnerability.modules"
            << "." << keyName;

        module.vulnPcs = config->getIntegerList(ss0.str() + ".vulnerabilities");
        assert(module.vulnPcs.size() >= 1);

        std::vector<const ControlFlowGraph::BasicBlock *> bbList;
        if (!m_cfg->getBasicBlockRange(moduleConfig.moduleName, 0, UINT64_MAX - 1, bbList)) {
            m_plg->getWarningsStream() << "have no basic blocks for module " << moduleConfig.moduleName << "\n";
            exit(-1);
        }
        assert(bbList.size());

        for (unsigned i = 0; i < bbList.size(); i++) {
            module.bbMap[bbList[i]->start_pc] = bbList[i];
        }
    }
}

void CUPAVulnerabilitySearcherClass::onTranslateInstruction(ExecutionSignal *signal, S2EExecutionState *state,
                                                            TranslationBlock *tb, uint64_t pc) {
    const ModuleDescriptor *moduleDescriptor = m_detector->getCurrentDescriptor(state);
    if (moduleDescriptor) {
        assert(m_modules.find(moduleDescriptor->Name) != m_modules.end());
        Module &module = m_modules[moduleDescriptor->Name];

        for (unsigned v = 0; v < module.vulnPcs.size(); v++) {
            if (module.vulnPcs[v] == pc) {
                signal->connect(sigc::mem_fun(*this, &CUPAVulnerabilitySearcherClass::onInstructionExecution));
            }
        }
    }
}

void CUPAVulnerabilitySearcherClass::onInstructionExecution(S2EExecutionState *state, uint64_t pc) {
    m_plg->getWarningsStream(state) << "reached vulnerability " << hexval(pc) << "\n";
}

void CUPAVulnerabilitySearcherClass::onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module) {

    if (m_modules.find(module.Name) != m_modules.end()) {
        if (func_call_conn.connected())
            return;
        FunctionMonitor::CallSignal *cs = m_functionMonitor->getCallSignal(state, -1, module.AddressSpace);
        func_call_conn = cs->connect(sigc::mem_fun(*this, &CUPAVulnerabilitySearcherClass::onFunctionCall));
    }
}

void CUPAVulnerabilitySearcherClass::onFunctionCall(S2EExecutionState *state, FunctionMonitorState *fns) {
    uint64_t retPc;
    bool ok = state->getReturnAddress(&retPc);
    assert(ok);

    DECLARE_PLUGINSTATE_P(m_plg, CUPAVulnerabilitySearcherState, state);
    plgState->pushRet(retPc);
}

void CUPAVulnerabilitySearcherClass::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                         TranslationBlock *tb, uint64_t pc, bool hasStaticTarget,
                                                         uint64_t staticPc) {
    if (tb->se_tb_type == TB_RET) {
        const ModuleDescriptor *moduleDescriptor = m_detector->getCurrentDescriptor(state);
        if (moduleDescriptor && m_modules.find(moduleDescriptor->Name) != m_modules.end()) {
            signal->connect(sigc::mem_fun(*this, &CUPAVulnerabilitySearcherClass::onReturnExecutionComplete));
        }
    }
}

void CUPAVulnerabilitySearcherClass::onReturnExecutionComplete(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE_P(m_plg, CUPAVulnerabilitySearcherState, state);
    const std::vector<uint64_t> &retStack = plgState->getRetStack();

    if (retStack.back() != state->getPc()) { // TODO: this happens because we do not handle CBs terminate syscall
        llvm::raw_ostream &s = m_plg->getWarningsStream(state);
        s << "Returning to PC " << hexval(state->getPc()) << " that is not in return stack: ";
        for (unsigned j = 0; j < retStack.size(); j++) {
            s << hexval(retStack[j]) << (j != retStack.size() - 1 ? ", " : "");
        }
        s << "\n";

        return;
    }

    plgState->popRet();
}

/*
 *
 */

distance_t CUPAVulnerabilitySearcherClass::getRetDistance(Module &module, uint64_t pc, std::set<uint64_t> &visitedPcs) {
    visitedPcs.insert(pc);

    BasicBlocksMap::const_iterator bbIt = module.bbMap.find(pc);
    assert(bbIt != module.bbMap.end());
    const ControlFlowGraph::BasicBlock *bb = bbIt->second;

    distance_t bbSize = 1;
    distance_t minDist = DISTANCE_MAX;

    if (bb->call_target) {
        bbSize += getRetDistance(module, bb->call_target);
    }

    if (!bb->successors.size()) {
        return bbSize;
    }

    foreach2 (it, bb->successors.begin(), bb->successors.end()) {
        if (visitedPcs.find(*it) == visitedPcs.end()) {
            distance_t d = getRetDistance(module, *it, visitedPcs);
            d += std::min(bbSize, DISTANCE_MAX - d);

            minDist = std::min(minDist, d);
        }
    }

    return minDist;
}

bool CUPAVulnerabilitySearcherClass::canReachVulnerability(Module &module, uint64_t pc, uint64_t vulnPc,
                                                           std::set<uint64_t> &visitedPcs) {
    visitedPcs.insert(pc);

    BasicBlocksMap::const_iterator bbIt = module.bbMap.find(pc);
    assert(bbIt != module.bbMap.end());
    const ControlFlowGraph::BasicBlock *bb = bbIt->second;

    if (bb->start_pc <= vulnPc && vulnPc <= bb->end_pc) {
        return true;
    }

    if (bb->call_target) {
        if (canReachVulnerability(module, bb->call_target, vulnPc)) {
            return true;
        }
    }

    foreach2 (it, bb->successors.begin(), bb->successors.end()) {
        if (visitedPcs.find(*it) == visitedPcs.end()) {
            if (canReachVulnerability(module, *it, vulnPc, visitedPcs)) {
                return true;
            }
        }
    }

    return false;
}

distance_t CUPAVulnerabilitySearcherClass::getVulnerabilityDistance(Module &module, uint64_t pc, uint64_t vulnPc,
                                                                    std::set<uint64_t> &visitedPcs) {
    visitedPcs.insert(pc);

    BasicBlocksMap::const_iterator bbIt = module.bbMap.find(pc);
    assert(bbIt != module.bbMap.end());
    const ControlFlowGraph::BasicBlock *bb = bbIt->second;

    if (bb->start_pc <= vulnPc && vulnPc <= bb->end_pc) {
        return 0;
    }

    distance_t bbSize = 1;
    distance_t minDist = DISTANCE_MAX;

    if (bb->call_target) {
        if (canReachVulnerability(module, bb->call_target, vulnPc)) {
            distance_t d = getVulnerabilityDistance(module, bb->call_target, vulnPc);
            d += std::min(bbSize, DISTANCE_MAX - d);

            minDist = d;
        } else {
            bbSize += getRetDistance(module, bb->call_target);
        }
    }

    foreach2 (it, bb->successors.begin(), bb->successors.end()) {
        if (visitedPcs.find(*it) == visitedPcs.end()) {
            distance_t d = getVulnerabilityDistance(module, *it, vulnPc, visitedPcs);
            d += std::min(bbSize, DISTANCE_MAX - d);

            minDist = std::min(minDist, d);
        }
    }

    return minDist;
}

/*
 *
 */

distance_t CUPAVulnerabilitySearcherClass::getRetDistance(Module &module, uint64_t pc) {
    std::map<uint64_t, distance_t>::const_iterator it;
    it = module.retDist.find(pc);

    if (it != module.retDist.end()) {
        return it->second;
    } else {
        std::set<uint64_t> visitedPcs;
        distance_t d = getRetDistance(module, pc, visitedPcs);
        module.retDist[pc] = d;
        return d;
    }
}

bool CUPAVulnerabilitySearcherClass::canReachVulnerability(Module &module, uint64_t pc, uint64_t vulnPc) {
    std::map<std::pair<uint64_t, uint64_t>, bool>::const_iterator it;
    std::pair<uint64_t, uint64_t> mapId = std::make_pair(pc, vulnPc);
    it = module.canReachVuln.find(mapId);

    if (it != module.canReachVuln.end()) {
        return it->second;
    } else {
        std::set<uint64_t> visitedPcs;
        bool r = canReachVulnerability(module, pc, vulnPc, visitedPcs);
        module.canReachVuln[mapId] = r;
        return r;
    }
}

distance_t CUPAVulnerabilitySearcherClass::getVulnerabilityDistance(Module &module, uint64_t pc, uint64_t vulnPc) {
    std::map<std::pair<uint64_t, uint64_t>, distance_t>::const_iterator it;
    std::pair<uint64_t, uint64_t> mapId = std::make_pair(pc, vulnPc);
    it = module.vulnDist.find(mapId);

    if (it != module.vulnDist.end()) {
        return it->second;
    } else {
        std::set<uint64_t> visitedPcs;
        distance_t d = getVulnerabilityDistance(module, pc, vulnPc, visitedPcs);
        module.vulnDist[mapId] = d;
        return d;
    }
}

distance_t CUPAVulnerabilitySearcherClass::getVulnerabilityDistance(Module &module, uint64_t pc, uint64_t vulnPc,
                                                                    const std::vector<uint64_t> &retStack) {
    distance_t minDist = getVulnerabilityDistance(module, pc, vulnPc);
    distance_t retDist = getRetDistance(module, pc);

    for (int i = retStack.size() - 1; i >= 0; i--) {
        distance_t d = getVulnerabilityDistance(module, retStack[i], vulnPc);
        d += std::min(retDist, DISTANCE_MAX - d);

        minDist = std::min(minDist, d);
        retDist += getRetDistance(module, retStack[i]);
    }

    return minDist;
}

/*
 *
 */

void CUPAVulnerabilitySearcherClass::onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                                            const std::vector<klee::ref<klee::Expr>> &newConditions) {
    assert(newStates.size() == 2);

    const ModuleDescriptor *moduleDescriptor = m_detector->getCurrentDescriptor(state);
    if (!moduleDescriptor) {
        // Probably this is a fork within a kernel
        return;
    }

    assert(m_modules.find(moduleDescriptor->Name) != m_modules.end());
    Module &module = m_modules[moduleDescriptor->Name];

    DECLARE_PLUGINSTATE_P(m_plg, CUPAVulnerabilitySearcherState, state);
    const std::vector<uint64_t> &retStack = plgState->getRetStack();

    uint64_t nextPc[2];
    if (!state->getStaticBranchTargets(&nextPc[0], &nextPc[1])) {
        const ControlFlowGraph::BasicBlock *bb = m_cfg->findBasicBlock(moduleDescriptor->Name, state->getPc());
        assert(bb);
        nextPc[0] = nextPc[1] = bb->start_pc; // BB precision is enough, no need for exact PC
    }

    for (int i = 0; i < 2; i++) {
        std::vector<distance_t> distances;
        for (unsigned v = 0; v < module.vulnPcs.size(); v++) {
            distance_t d = getVulnerabilityDistance(module, nextPc[i], module.vulnPcs[v], retStack);
            distances.push_back(d);
        }

        DECLARE_PLUGINSTATE_P(m_plg, CUPAVulnerabilitySearcherState, newStates[i]);
        plgState->setDistances(distances);
    }

    m_plg->s2e()->getExecutor()->yieldState(*state);
}

void CUPAVulnerabilitySearcherClass::update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                                            const klee::StateSet &removedStates) {
    StateSet states;

    CUPASearcherClass::update(current, addedStates, removedStates);
    foreach2 (it, addedStates.begin(), addedStates.end()) {
        S2EExecutionState *state = static_cast<S2EExecutionState *>(*it);
        states.insert(state);
    }

    foreach2 (it, removedStates.begin(), removedStates.end()) {
        S2EExecutionState *state = static_cast<S2EExecutionState *>(*it);
        states.erase(state);
        m_states.erase(state);
    }

    foreach2 (it, states.begin(), states.end()) { m_states.insert(*it); }
}

klee::ExecutionState &CUPAVulnerabilitySearcherClass::selectState() {
    if (rand() % 100 < m_useParentSearcherProbability) {
        m_plg->getWarningsStream() << "Fall back to next searcher\n";
        return CUPASearcherClass::selectState();
    }

    assert(!m_states.empty());

    if (m_states.size() == 1) {
        return **m_states.begin();
    }

    S2EExecutionState *state = NULL;
    distance_t minDist = DISTANCE_MAX;
    int rnd = rand();

    // TODO: one module is supported, rewrite random state selection to work with multiple modules
    assert(m_modules.size() == 1);

    foreach2 (it, m_states.begin(), m_states.end()) {
        DECLARE_PLUGINSTATE_P(m_plg, CUPAVulnerabilitySearcherState, *it);

        const std::vector<distance_t> &distances = plgState->getDistances();
        assert(distances.size());

        int vulnN = rnd % distances.size();
        distance_t distance = distances[vulnN];

        if (distance <= minDist) {
            state = *it;
            minDist = distance;
        }
    }
    assert(state);

    return *state;
}

bool CUPAVulnerabilitySearcherClass::empty() {
    return m_states.empty();
}

/*
 *
 */
CUPAVulnerabilitySearcherState::CUPAVulnerabilitySearcherState() {
}

CUPAVulnerabilitySearcherState::~CUPAVulnerabilitySearcherState() {
}

CUPAVulnerabilitySearcherState *CUPAVulnerabilitySearcherState::clone() const {
    return new CUPAVulnerabilitySearcherState(*this);
}

PluginState *CUPAVulnerabilitySearcherState::factory(Plugin *p, S2EExecutionState *s) {
    return new CUPAVulnerabilitySearcherState();
}

void CUPAVulnerabilitySearcherState::setDistances(const std::vector<distance_t> &distances) {
    m_distances = distances;
}

const std::vector<distance_t> &CUPAVulnerabilitySearcherState::getDistances() const {
    return m_distances;
}

void CUPAVulnerabilitySearcherState::pushRet(uint64_t retPc) {
    m_retStack.push_back(retPc);
}

void CUPAVulnerabilitySearcherState::popRet() {
    assert(m_retStack.size());

    m_retStack.pop_back();
}

const std::vector<uint64_t> &CUPAVulnerabilitySearcherState::getRetStack() const {
    return m_retStack;
}

} // namespace plugins
} // namespace s2e
