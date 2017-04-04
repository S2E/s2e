///
/// Copyright (C) 2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/cpu.h>

#include <boost/regex.hpp>
#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/Linux/DecreeMonitor.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include "PathSearcher.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(PathSearcher, "Choose fork branches that lead to desired state", "PathSearcher", //
                  "DecreeMonitor");

PathSearcher::PathSearcher(S2E *s2e) : Plugin(s2e) {
    m_chosenState = NULL;
    m_vulnPc = 0;
}

void PathSearcher::initialize() {
    s2e()->getExecutor()->setSearcher(this);

    CorePlugin *core = s2e()->getCorePlugin();
    core->onStateFork.connect_front(sigc::mem_fun(*this, &PathSearcher::onFork));
    core->onTranslateInstructionStart.connect(sigc::mem_fun(*this, &PathSearcher::onTranslateInstruction));
    s2e()->getPlugin<DecreeMonitor>()->onSegFault.connect(sigc::mem_fun(*this, &PathSearcher::onSegFault));

    ConfigFile *config = s2e()->getConfig();

    m_vulnPc = config->getInt(getConfigKey() + ".vulnPc", 0);

    const uint64_t originalDesiredStateId = config->getInt(getConfigKey() + ".stateId", 0);
    if (!originalDesiredStateId) {
        getWarningsStream() << "please specify stateId\n";
        exit(-1);
    }

    const ConfigFile::string_list logFiles = config->getStringList(getConfigKey() + ".logFiles");
    if (!logFiles.size()) {
        getWarningsStream() << "please specify logFiles\n";
        exit(-1);
    }

    const std::string executionTrace = config->getString(getConfigKey() + ".executionTrace", "");

    typedef struct {
        uint64_t pc;
        uint64_t parentStateId;
        uint64_t childStateId[2];
    } forkInfo;

#define FORKED_STATE_ID(fi) \
    ((fi)->parentStateId == (fi)->childStateId[0] ? (fi)->childStateId[1] : (fi)->childStateId[0])

    std::vector<forkInfo> forkData;

    foreach2 (it, logFiles.begin(), logFiles.end()) {
        std::ifstream file(it->c_str(), std::ios::in);
        if (!file.is_open()) {
            getWarningsStream() << "failed to open file \"" + *it + "\"\n";
            exit(-1);
        }

        const boost::regex forkRegex(".* Forking state ([[:digit:]]+) at pc = 0x([[:xdigit:]]+) .*");
        const boost::regex stateRegex("    state ([[:digit:]]+)");

        std::string line;
        while (std::getline(file, line)) {
            boost::smatch match;
            if (boost::regex_match(line, match, forkRegex)) {
                char *p;
                forkInfo fi;

                assert(match.size() == 3);
                fi.parentStateId = strtoull(((std::string) match[1]).c_str(), &p, 10);
                assert(*p == '\0');
                fi.pc = strtoull(((std::string) match[2]).c_str(), &p, 16);
                assert(*p == '\0');

                for (int i = 0; i < 2; i++) {
                    if (!std::getline(file, line) || !boost::regex_match(line, match, stateRegex)) {
                        getWarningsStream() << "no next line for forked state " << fi.parentStateId << "\n";
                        exit(-1);
                    }
                    assert(match.size() == 2);
                    fi.childStateId[i] = strtoull(((std::string) match[1]).c_str(), &p, 10);
                    assert(*p == '\0');
                }

                assert(fi.parentStateId == fi.childStateId[0] || fi.parentStateId == fi.childStateId[1]);

                forkData.push_back(fi);
            }
        }
    }
    assert(forkData.size());

    getWarningsStream() << "read " << forkData.size() << " fork points\n";

    std::vector<std::vector<forkInfo>::const_iterator> forkPoints;

    uint64_t desiredStateId = originalDesiredStateId;
    uint64_t prevStateId = UINT64_MAX;
    while (true) {
        uint64_t parentStateId;
        bool hasParentState = false;
        std::vector<std::vector<forkInfo>::const_iterator> tmpForkPoints;

        // Remember all points where desiredState has forked
        foreach2 (it, forkData.begin(), forkData.end()) {
            if (it->parentStateId == desiredStateId) {
                if (tmpForkPoints.size()) {
                    std::vector<forkInfo>::const_iterator prevIt = *(tmpForkPoints.end() - 1);
                    if (FORKED_STATE_ID(prevIt) >= FORKED_STATE_ID(it)) {
                        getWarningsStream() << "TODO: sort fork points by childId\n";
                        getWarningsStream() << "      " << prevIt->parentStateId << " (" << prevIt->childStateId[0]
                                            << ", " << prevIt->childStateId[1] << ")\n";
                        getWarningsStream() << "      " << it->parentStateId << " (" << it->childStateId[0] << ", "
                                            << it->childStateId[1] << ")\n";
                        exit(-1);
                    }
                }
                tmpForkPoints.push_back(it);
            } else if (it->childStateId[0] == desiredStateId || it->childStateId[1] == desiredStateId) {
                assert(!hasParentState);
                parentStateId = it->parentStateId;
                hasParentState = true;
            }
        }

        // Copy points until desiredState has forked into prevState
        foreach2 (it, tmpForkPoints.rbegin(), tmpForkPoints.rend()) {
            if ((*it)->childStateId[0] <= prevStateId && (*it)->childStateId[1] <= prevStateId) {
                forkPoints.push_back(*it);
            }
        }

        if (desiredStateId == 0) {
            break;
        }

        assert(hasParentState);
        prevStateId = desiredStateId;
        desiredStateId = parentStateId;
    }
    assert(forkPoints.size());

    getWarningsStream() << "path that leads to state " << originalDesiredStateId << ":\n";
    foreach2 (it, forkPoints.rbegin(), forkPoints.rend()) {
        const forkInfo &fi = **it;
        getWarningsStream() << "    fork state " << fi.parentStateId << " at " << hexval(fi.pc) << ": "
                            << fi.childStateId[0] << " " << fi.childStateId[1] << "\n";
    }

    foreach2 (it, forkPoints.rbegin(), forkPoints.rend()) {
        const forkInfo &fi = **it;
        uint64_t nextStateId;
        forkDirector fd;

        fd.pc = fi.pc;

        if (it != forkPoints.rend() - 1) {
            const forkInfo &nextFi = **(it + 1);
            nextStateId = nextFi.parentStateId;
        } else {
            nextStateId = originalDesiredStateId;
        }

        if (nextStateId == fi.childStateId[0]) {
            fd.id = 0;
        } else if (nextStateId == fi.childStateId[1]) {
            fd.id = 1;
        } else {
            getWarningsStream() << "invalid fork\n";
            exit(-1);
        }

        m_forkDirectors.push_back(fd);
    }

    getWarningsStream() << "branches to be chosen:\n";
    foreach2 (it, m_forkDirectors.begin(), m_forkDirectors.end()) {
        const forkDirector &fd = *it;
        getWarningsStream() << "    #" << it - m_forkDirectors.begin() << " at " << hexval(fd.pc) << ": " << fd.id
                            << "\n";
    }

    if (executionTrace.length()) {
        std::ifstream file(executionTrace.c_str(), std::ios::in);
        if (!file.is_open()) {
            getWarningsStream() << "failed to open file \"" + executionTrace + "\"\n";
            exit(-1);
        }

        const boost::regex forkRegex("Forked at 0x([[:xdigit:]]+) .*");
        unsigned forkN = 0;

        std::string line;
        while (std::getline(file, line)) {
            boost::smatch match;
            if (boost::regex_match(line, match, forkRegex)) {
                char *p;
                assert(match.size() == 2);
                uint64_t forkPc = strtoull(((std::string) match[1]).c_str(), &p, 16);
                assert(*p == '\0');

                assert(forkN < m_forkDirectors.size());
                if (m_forkDirectors[forkN].pc != forkPc) {
                    getWarningsStream() << "fork PC mismatch with execution trace\n";
                    exit(-1);
                }

                forkN++;
            }
        }

        if (forkN != m_forkDirectors.size()) {
            getWarningsStream() << "fork count mismatch with execution trace\n";
            exit(-1);
        }

        getWarningsStream() << "execution trace matched\n";
    }
}

/*
 *
 */

void PathSearcher::onTranslateInstruction(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                          uint64_t pc) {
    if (m_vulnPc && pc == m_vulnPc) {
        signal->connect(sigc::mem_fun(*this, &PathSearcher::onInstructionExecution));
    }
}

void PathSearcher::onInstructionExecution(S2EExecutionState *state, uint64_t pc) {
    getWarningsStream(state) << "reached vulnerability " << hexval(pc) << "\n";
    uint64_t eax = state->regs()->read<target_ulong>(offsetof(CPUX86State, regs[R_EAX]));
    uint64_t ecx = state->regs()->read<target_ulong>(offsetof(CPUX86State, regs[R_ECX]));
    getWarningsStream(state) << "EAX=" << hexval(eax) << ", ECX=" << hexval(ecx) << "\n";
}

void PathSearcher::onSegFault(S2EExecutionState *state, uint64_t pid, uint64_t pc) {
    getWarningsStream(state) << "SEGFAULT reached\n";
    exit(0);
}

void PathSearcher::onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                          const std::vector<klee::ref<klee::Expr>> &newConditions) {
    assert(newStates.size() == 2);

    DECLARE_PLUGINSTATE(PathSearcherState, state);
    unsigned forkCount = plgState->getForkCount();

    getWarningsStream(state) << "fork #" << forkCount << " out of #" << m_forkDirectors.size() << "\n";

    assert(forkCount < m_forkDirectors.size());
    const forkDirector &fd = m_forkDirectors[forkCount];

    if (fd.pc != state->getPc()) {
        getWarningsStream(state) << "fork PC mismatch: " << hexval(fd.pc) << " != " << hexval(state->getPc()) << "\n";
        exit(-1);
    }

    assert(fd.id == 0 || fd.id == 1);
    m_chosenState = newStates[fd.id];

    for (int i = 0; i < 2; i++) {
        DECLARE_PLUGINSTATE(PathSearcherState, newStates[i]);
        plgState->increaseForkCount();
    }

    s2e()->getExecutor()->yieldState(*state);
}

void PathSearcher::update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                          const klee::StateSet &removedStates) {
    StateSet states;

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

klee::ExecutionState &PathSearcher::selectState() {
    if (m_states.size() == 1) {
        return **m_states.begin();
    }

    assert(m_states.find(m_chosenState) != m_states.end());
    return *m_chosenState;
}

bool PathSearcher::empty() {
    return m_states.empty();
}

/*
 *
 */

PathSearcherState::PathSearcherState() {
    m_forkCount = 0;
}

PathSearcherState::~PathSearcherState() {
}

PathSearcherState *PathSearcherState::clone() const {
    return new PathSearcherState(*this);
}

PluginState *PathSearcherState::factory(Plugin *p, S2EExecutionState *s) {
    return new PathSearcherState();
}

void PathSearcherState::increaseForkCount() {
    m_forkCount++;
}

unsigned PathSearcherState::getForkCount() const {
    return m_forkCount;
}

} // namespace plugins
} // namespace s2e
