///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
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

#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>
#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>

#include <random>
#include <sstream>

#include <boost/regex.hpp>

#include "SeedSearcher.h"

namespace s2e {
namespace plugins {
namespace seeds {

S2E_DEFINE_PLUGIN(SeedSearcher, "Seed searcher", "", "MultiSearcher", "CUPASearcher");

namespace {

class SeedSearcherState : public PluginState {
public:
    /// Tracks which seed was used to find this subtree
    uint64_t seedIndex;

    /// Indicates that this is the main path of the seed
    bool seedState;

    SeedSearcherState() : seedIndex(-1), seedState(false){};

    virtual SeedSearcherState *clone() const {
        SeedSearcherState *ret = new SeedSearcherState(*this);
        ret->seedState = false;
        return ret;
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new SeedSearcherState();
    }

    virtual ~SeedSearcherState() {
    }
};
} // namespace

void SeedSearcher::initialize() {

    ConfigFile *cfg = s2e()->getConfig();

    bool ok = false;

    CorePlugin *plg = s2e()->getCorePlugin();

    m_timer = plg->onTimer.connect(sigc::mem_fun(*this, &SeedSearcher::onTimer));
    plg->onStateFork.connect(sigc::mem_fun(*this, &SeedSearcher::onStateFork));
    plg->onStateKill.connect(sigc::mem_fun(*this, &SeedSearcher::onStateKill));

    // \todo reuse directories from HostFiles.
    m_seedDirectory = cfg->getString(getConfigKey() + ".seedDirectory", "", &ok);
    if (!ok) {
        getWarningsStream() << "Please specify seedDirectory\n";
        exit(-1);
    }

    if (!llvm::sys::fs::exists(m_seedDirectory)) {
        getWarningsStream() << m_seedDirectory << " does not exist\n";
        exit(-1);
    }

    m_selectSeedState = false;
    m_usedSeedsCount = 0;

    m_cupa = s2e()->getPlugin<CUPASearcher>();
    m_multiSearcher = s2e()->getPlugin<MultiSearcher>();

    m_multiSearcher->registerSearcher("SeedSearcher", this);

    m_cachedState = nullptr;
    m_initialState = nullptr;

    m_initialStateHasSeedFile = false;

    m_backupSeeds = cfg->getBool(getConfigKey() + ".backupSeeds", true);
    m_enableSeeds = cfg->getBool(getConfigKey() + ".enableSeeds");
    m_maxSeedStates = cfg->getInt(getConfigKey() + ".maxSeedStates");
    m_parallelSeeds = cfg->getBool(getConfigKey() + ".enableParallelSeeding", true);

    if (m_parallelSeeds) {
        plg->onStatesSplit.connect(sigc::mem_fun(*this, &SeedSearcher::onStateSplit));
        plg->onProcessForkComplete.connect(sigc::mem_fun(*this, &SeedSearcher::onProcessForkComplete));
    }

    if (m_backupSeeds) {
        m_seedBackupDirectory = s2e()->getOutputFilename("seeds-backup");
        auto error = llvm::sys::fs::create_directory(m_seedBackupDirectory);
        if (error) {
            getWarningsStream() << "Could not create " << m_seedBackupDirectory << '\n';
            exit(-1);
        }
    }
}

void SeedSearcher::switchToCUPA() {
    m_multiSearcher->selectSearcher("CUPASearcher");
}

void SeedSearcher::switchToSeedSearcher() {
    m_multiSearcher->selectSearcher("SeedSearcher");
}

/// We want to keep state 0 in all S2E instances in
/// order to be able to fetch seeds in parallel.
void SeedSearcher::onStateSplit(klee::StateSet &parent, klee::StateSet &child) {
    if (m_initialState) {
        parent.insert(m_initialState);
        child.insert(m_initialState);
    }
}

void SeedSearcher::updateIdleStatus() {
    Seed s;
    bool idle = !getTopPrioritySeed(s) && s2e()->getExecutor()->getStatesCount() == 1;
    unsigned index = s2e()->getCurrentInstanceIndex();
    SeedStats *stats = m_globalStats.acquire();
    stats->idle[index] = idle;
    getDebugStream() << "idle setting: idx=" << index << " idle=" << idle << "\n";
    m_globalStats.release();
}

void SeedSearcher::getSeedStats(SeedStats &stats) {
    SeedStats *s = m_globalStats.acquire();
    stats = *s;
    m_globalStats.release();
}

void SeedSearcher::onProcessForkComplete(bool isChild) {
    if (isChild) {
        m_usedSeedsCount = 0;
    }
}

void SeedSearcher::onStateFork(S2EExecutionState *oldState, const std::vector<S2EExecutionState *> &newStates,
                               const std::vector<klee::ref<klee::Expr>> &) {
    // Initial state becomes seed state when it forks after getting seed file
    if (oldState == m_initialState && m_initialStateHasSeedFile) {
        m_initialStateHasSeedFile = false;
        for (auto it : newStates) {
            if (it != oldState) {
                getDebugStream(oldState) << "Forked new seed state " << it->getID() << "\n";
                m_seedStates.insert(it);

                DECLARE_PLUGINSTATE(SeedSearcherState, it);
                // State 0 can fork a state for exploration without seeds.
                // The forked state has no seed index and therefore must
                // not be marked as seed state.
                if ((int) plgState->seedIndex != -1) {
                    plgState->seedState = true;
                }
            }
        }
    }
}

void SeedSearcher::onStateKill(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(SeedSearcherState, state);
    if (plgState->seedState) {
        // States can me moved between instances, one must
        // therefore attach the seed status to the state itself.
        // It is not possible to just look at m_seedStates set
        // because it is local to the S2E instance that does seeding.
        Seed seed = m_availableSeeds.getUsedSeed(plgState->seedIndex);
        onSeed.emit(seed, TERMINATED);
    }
}

void SeedSearcher::update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                          const klee::StateSet &removedStates) {
    S2EExecutionState *cs = dynamic_cast<S2EExecutionState *>(current);
    if (!m_initialState) {
        if (cs->getID() == 0) {
            m_initialState = cs;
        }
    }

    for (auto addedState : addedStates) {
        S2EExecutionState *es = dynamic_cast<S2EExecutionState *>(addedState);
        m_states.insert(es);
    }

    for (auto removedState : removedStates) {
        S2EExecutionState *es = dynamic_cast<S2EExecutionState *>(removedState);

        // This can only happen if state 0 dies for some reason
        if (es == m_initialState) {
            s2e_warn_assert(cs, false, "Initial state no longer exists, seed look up is not possible");
            m_initialState = nullptr;
            m_selectSeedState = false;
        }

        if (es == m_cachedState) {
            m_cachedState = nullptr;
        }
        m_seedStates.erase(es);
        m_states.erase(es);
    }

    // Always prefer seed states
    if (m_seedStates.size()) {
        switchToSeedSearcher();
    }
}

klee::ExecutionState &SeedSearcher::selectState() {
    // Found new seed file, let initial state use it.
    // We want to prioritize state 0 as soon as new seeds
    // are available. Otherwise, it might never be scheduled
    // if some other seed state gets stuck.
    //
    // We also have to wait until state 0 actually forks the
    // seed state, and inserts the forked state into m_seedStates,
    // otherwise, switching to CUPA searcher may be done too early.
    if ((m_initialState && m_selectSeedState) || m_initialStateHasSeedFile) {
        return *m_initialState;
    }

    // Run previously selected seed state until it is terminated
    // TODO: seed states may get stuck in the solver sometimes.
    // On a single core, DFS will lead to infinite time.
    // TODO: have a timeout mechanism to switch to CUPA
    if (m_cachedState) {
        return *m_cachedState;
    }

    auto it = m_seedStates.begin();
    if (it != m_seedStates.end()) {
        m_cachedState = *it;
        return *m_cachedState;
    }

    // No more seed states, and no new seed files, revert to CUPA
    switchToCUPA();
    assert(m_states.size() > 0);
    return **m_states.begin();
}

bool SeedSearcher::empty() {
    return m_states.empty();
}

void SeedSearcher::backupSeed(const std::string &seedFilePath) {
    auto fileName = std::string(llvm::sys::path::filename(seedFilePath));

    std::stringstream destination;
    destination << m_seedBackupDirectory << "/" << fileName;
    auto error = llvm::sys::fs::copy_file(seedFilePath, destination.str());
    if (error) {
        getWarningsStream() << "Could not backup " << seedFilePath << " to " << destination.str() << "\n";
        return;
    }

    // Copy the symbolic ranges file if it's present.
    auto symRangesPath = seedFilePath + ".symranges";
    if (llvm::sys::fs::exists(symRangesPath)) {
        destination << ".symranges";
        llvm::sys::fs::copy_file(symRangesPath, destination.str());
        if (error) {
            getWarningsStream() << "Could not backup " << symRangesPath << " to " << destination.str() << "\n";
            return;
        }
    }
}

void SeedSearcher::fetchNewSeeds() {
    // First group is the seed index, second group is the priority,
    // the remainder of the string is the optional suffix.
    static const boost::regex filePattern("(\\d+)-(\\d+).*", boost::regex::perl);

    std::error_code error;
    unsigned count = 0;

    // TODO: this might get expensive if there are many files.
    // Better to monitor directory for changes.
    for (llvm::sys::fs::directory_iterator i(m_seedDirectory, error), e; i != e; i.increment(error)) {
        std::string entry = i->path();
        auto status = i->status();

        if (!status) {
            getWarningsStream() << "Error when querying " << entry << " - " << status.getError().message() << '\n';
            continue;
        }

        if (status->type() == llvm::sys::fs::file_type::directory_file) {
            continue;
        }

        boost::smatch what;
        auto fileName = std::string(llvm::sys::path::filename(entry));
        if (!boost::regex_match(fileName, what, filePattern)) {
            getWarningsStream() << entry << " is not a valid seed name\n";
            continue;
        }

        // Skip symbolic map
        if (fileName.find(".symranges") != std::string::npos) {
            continue;
        }

        if (what.size() != 3) {
            continue;
        }

        std::string indexStr = what[1];
        std::string priorityStr = what[2];

        Seed seed;
        seed.filename = fileName;
        seed.index = atoi(indexStr.c_str());
        seed.priority = atoi(priorityStr.c_str());
        seed.queuedTimestamp = std::chrono::steady_clock::now();

        // Number of seeds can be huge, don't want to clutter the logs
        if (count < 5) {
            getDebugStream() << "name: " << seed.filename << " index:" << seed.index << " priority:" << seed.priority
                             << "\n";
        } else if (count == 5) {
            getDebugStream() << "Reached max display count, further seeds won't be displayed\n";
        }

        if (m_backupSeeds) {
            backupSeed(entry);
        }

        ++count;

        if (!m_processedSeeds.count(seed.index)) {
            m_availableSeeds.queue(seed);
            m_processedSeeds.insert(seed.index);
            onSeed.emit(seed, QUEUED);
        }
    }

    getDebugStream() << "Fetched " << count << " valid seeds\n";
}

bool SeedSearcher::scheduleNextSeed() {
    if (m_availableSeeds.size() == 0) {
        return false;
    }

    if (m_selectSeedState) {
        return false;
    }

    // By default, we don't wait that m_seedStates becomes empty:
    //
    // 1. We may be interested in getting as many
    // seeds as possible. This is the default behavior.
    // Client plugins can customize it by disabling seeds
    // whenever they want.
    //
    // 2. Seeds may get stuck, preventing any progress.
    // Continuously fetching seeds ensures that path exploration
    // can still continue.
    //
    // 3. This is a matter of policy to be implemented by some
    // other plugin.
    //
    // For convenience, a configuration option can override this.
    if (m_maxSeedStates > 0) {
        if (m_seedStates.size() >= m_maxSeedStates) {
            getDebugStream() << " Reached maximum number of seed states "
                             << "(" << m_maxSeedStates << ")\n";
            return false;
        }
    }

    // Take the highest priority seed first
    //
    // The method ensures that concurrently-running instances
    // do not grab the same seeds. There shouldn't be any
    // starvation issues, because instances would take a
    // long time to process a seed, giving plenty of time
    // for others to get other seeds.
    bool ret = m_availableSeeds.dequeue(m_currentSeed);
    if (!ret) {
        getDebugStream() << "Synchronized dequeue failed\n";
        onSeed.emit(Seed(), SCHEDULING_FAILED);
        return false;
    }

    getInfoStream() << "  Scheduling seed " << m_currentSeed.filename << "\n";
    m_selectSeedState = true;

    onSeed.emit(m_currentSeed, SCHEDULED);

    return true;
}

void SeedSearcher::onTimer() {
    if (!m_initialState) {
        return;
    }

    updateIdleStatus();

    getDebugStream() << "Looking for new seeds\n";

    // Wait until initial state uses new seed file
    if (m_selectSeedState) {
        getDebugStream() << " Already found new seed\n";
        return;
    }

    // Keep fetching, can't wait until set of seeds is empty,
    // or somebody re-enables the seed searcher because
    // we could have high priority seeds coming unexpectedly,
    // and other plugins might want to know about it.
    fetchNewSeeds();

    if (!m_enableSeeds) {
        return;
    }

    if (scheduleNextSeed()) {
        switchToSeedSearcher();
    }
}

void SeedSearcher::handleGetSeedFile(S2EExecutionState *state, S2E_SEEDSEARCHER_COMMAND &cmd) {
    static bool alreadyExplored = false;
    DECLARE_PLUGINSTATE(SeedSearcherState, state);
    plgState->seedIndex = -1;

    getDebugStream(state) << "handleGetSeedFile\n";

    if (!m_selectSeedState) {
        if (m_states.size() > 1 || alreadyExplored) {
            cmd.GetFile.Result = 0;
        } else {
            alreadyExplored = true;
            cmd.GetFile.Result = 1;
        }

        getDebugStream(state) << "no seeds available\n";

        return;
    }

    unsigned length = std::min(cmd.GetFile.FileNameSizeInBytes, m_currentSeed.filename.length() + 1);

    if (!state->mem()->write(cmd.GetFile.FileName, m_currentSeed.filename.c_str(), length)) {
        getDebugStream(state) << "Could not write " << m_currentSeed.filename << " to " << hexval(cmd.GetFile.FileName)
                              << "\n";
        exit(-1);
    }

    getDebugStream(state) << "Written seed filename " << m_currentSeed.filename << "\n";

    m_selectSeedState = false;

    cmd.GetFile.Result = 2;

    if (state == m_initialState) {
        plgState->seedIndex = m_currentSeed.index;
        m_initialStateHasSeedFile = true;
        ++m_usedSeedsCount;

        SeedStats *stats = m_globalStats.acquire();
        ++stats->usedSeeds;
        m_globalStats.release();

        getDebugStream(state) << "UsedSeedCount: " << m_usedSeedsCount << "\n";
        onSeed.emit(m_currentSeed, FETCHED);
    }

    // now we expect initial state to fork, producing a seed state
}

uint64_t SeedSearcher::getSubtreeSeedIndex(S2EExecutionState *state) const {
    DECLARE_PLUGINSTATE_CONST(SeedSearcherState, state);
    return plgState->seedIndex;
}

unsigned SeedSearcher::getUsedSeedsCount(bool global) {
    if (global) {
        unsigned ret = 0;
        SeedStats *stats = m_globalStats.acquire();
        ret = stats->usedSeeds;
        m_globalStats.release();
        return ret;
    } else {
        return m_usedSeedsCount;
    }
}

void SeedSearcher::enableSeeds(bool enable) {
    if (enable && !m_enableSeeds) {
        getDebugStream() << "Enabling seeds\n";
    } else if (!enable && m_enableSeeds) {
        getDebugStream() << "Disabling seeds\n";
    }

    m_enableSeeds = enable;
}

bool SeedSearcher::isSeedState(S2EExecutionState *state) {
    return m_seedStates.find(state) != m_seedStates.end();
}

unsigned SeedSearcher::getPriorityCount() const {
    return m_availableSeeds.priorities();
}

void SeedSearcher::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
    S2E_SEEDSEARCHER_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "S2E_SEEDSEARCHER_COMMAND: mismatched command structure size " << guestDataSize
                                 << "\n";
        exit(-1);
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "S2E_SEEDSEARCHER_COMMAND: could not read transmitted data\n";
        exit(-1);
    }

    switch (command.Command) {
        case SEED_GET_SEED_FILE: {
            handleGetSeedFile(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }
        } break;

        case SEED_ENABLE_SEARCHER: {
            switchToSeedSearcher();
        } break;

        case SEED_DONE: {
            switchToCUPA();
        } break;

        default: {
            getWarningsStream(state) << "Invalid command " << hexval(command.Command) << "\n";
            exit(-1);
        }
    }
}

} // namespace seeds
} // namespace plugins
} // namespace s2e
