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

#ifndef S2E_PLUGINS_SEEDSEARCHER_H
#define S2E_PLUGINS_SEEDSEARCHER_H

#include <s2e/seed_searcher/commands.h>

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/Plugins/Searchers/MultiSearcher.h>
#include <s2e/Plugins/StaticAnalysis/ControlFlowGraph.h>
#include <s2e/Plugins/Support/KeyValueStore.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Synchronization.h>
#include <s2e/Utils.h>

#include <klee/Searcher.h>

#include <llvm/ADT/DenseSet.h>

#include <chrono>
#include <memory>
#include <queue>
#include <random>
#include <string>

#include "CUPASearcher.h"

namespace s2e {
namespace plugins {
namespace seeds {

///
/// \brief The Seed structure describes one seed.
///
/// The seed has an index and a priority, which are
/// derived from the file name.
///
struct Seed {
    std::string filename;
    unsigned priority;
    unsigned index;
    std::chrono::steady_clock::time_point queuedTimestamp;

    Seed() {
        priority = 0;
        index = 0;
    }
};

///
/// \brief The Seeds class manages a priority queue of seeds.
///
/// The queue sorts seeds by their priority and returns first
/// those with the highest priority.
///
class Seeds {

    static const unsigned MAX_SEEDS = 4096 * 8;

    ///
    /// \brief The SeedBitmap class allows keeping track of which
    /// seeds have already been used by other nodes.
    ///
    class SeedBitmap {
        // Use a hard-coded constant because it is easier to map
        // the structure into the address space of all S2E instances.
        uint8_t bits[MAX_SEEDS / 8] = {0};

    public:
        /// Returns true if the seed at the given index has already been used
        bool get(unsigned index) const {
            assert(index < MAX_SEEDS);
            return bits[index / 8] & (1 << (index % 8));
        }

        /// Sets the status of the seed
        void set(unsigned index, bool v) {
            bits[index / 8] |= 1 << (index % 8);
        }
    };

    struct SeedComparator {
        bool operator()(const Seed &a, const Seed &b) const {
            if (a.priority == b.priority) {
                // Lowest index has highest priority.
                // We want equal-priority test cases treated
                // in FIFO order.
                return a.index > b.index;
            }

            return a.priority < b.priority;
        }
    };

    typedef std::priority_queue<Seed, std::vector<Seed>, SeedComparator> AvailableSeeds;
    typedef llvm::DenseMap<unsigned, int> AvailablePriorities;
    typedef std::unordered_map<unsigned, Seed> UsedSeeds;

    AvailableSeeds m_seeds;
    AvailablePriorities m_priorities;
    UsedSeeds m_usedSeeds;

    // Map the bitmap in all S2E instances
    S2ESynchronizedObject<SeedBitmap> m_bitmap;

    ///
    /// \brief dequeue removes the highest priority seed from the queue
    /// and returns it to the caller.
    ///
    /// The caller must ensure that the queue is non-empty.
    ///
    /// \return the dequeued seed
    ///
    Seed doDequeue() {
        assert(m_seeds.size() > 0);
        Seed ret = m_seeds.top();
        m_seeds.pop();
        --m_priorities[ret.priority];
        assert(m_priorities[ret.priority] >= 0);
        m_usedSeeds[ret.index] = ret;
        return ret;
    }

public:
    ///
    /// \brief queue adds a seed \p s to the priority queue.
    ///
    void queue(const Seed &s) {
        m_seeds.push(s);
        ++m_priorities[s.priority];
    }

    ///
    /// \brief dequeue picks a seed that has not been used
    /// by any other instance yet.
    ///
    /// \param seed is the returned seed
    /// \return  false if no seed could be found, true otherwise
    ///
    bool dequeue(Seed &seed) {
        return pick(seed, true);
    }

    ///
    /// \brief pick the first available seed, with or without removing
    /// it from the queue.
    ///
    /// This function skips and cleans any seeds that have been picked
    /// by another instance.
    ///
    /// \param seed is the returned seed
    /// \param dequeue keep the seed in the queue if false
    /// \return true if a seed could be picked, false if no seeds are available
    ///
    bool pick(Seed &seed, bool dequeue) {
        bool ret = false;
        SeedBitmap *bmp = m_bitmap.acquire();

        while (m_seeds.size() > 0) {
            if (dequeue) {
                seed = doDequeue();
            } else {
                seed = m_seeds.top();
            }

            // Too many seeds to keep track of
            if (seed.index >= MAX_SEEDS) {
                break;
            }

            // Some other instance caught this seed
            if (bmp->get(seed.index)) {
                if (!dequeue) {
                    // Clean this seed, as it is used by someone else
                    doDequeue();
                }
                continue;
            }

            if (dequeue) {
                bmp->set(seed.index, true);
                assert(bmp->get(seed.index));
            }

            ret = true;
            break;
        }

        m_bitmap.release();
        return ret;
    }

    ///
    /// \brief size returns the number of seeds in the queue.
    ///
    unsigned size() const {
        return m_seeds.size();
    }

    ///
    /// \brief priorities returns the number of distinct priorities
    /// in the queue.
    ///
    /// For example, if the queue has 3 seeds with priorities 4, 1, 4,
    /// the function returns 2.
    ///
    unsigned priorities() const {
        return m_priorities.size();
    }

    ///
    /// \brief getUsedSeed returns a previously used seed
    ///
    /// The seed index must exist and be previously used.
    ///
    /// \param index of the seed to retrieve
    /// \return the seed that corresponds to the given index
    ///
    Seed getUsedSeed(unsigned index) const {
        auto it = m_usedSeeds.find(index);
        assert(it != m_usedSeeds.end());
        return (*it).second;
    }

    ///
    /// \brief getTopPrioritySeed returns the highest priority seed
    /// \param s the returned seed
    /// \return false if there are no seeds, true otherwise
    ///
    bool getTopPrioritySeed(Seed &s) {
        return pick(s, false);
    }
};

///
/// \brief The SeedEvent enum describes the type of action notified
/// by the onSeed event in the SeedSearcher class.
///
enum SeedEvent {
    /// The seed has been fetched from disk and put in a queue
    QUEUED,

    /// The searcher has scheduled state 0 for execution,
    /// which will fetch the given seed
    SCHEDULED,

    /// The searcher could not schedule the seed.
    /// This usually happen when another s2e instance preempted
    /// the last seed, and there is no seed left.
    /// The seed argument passed to the event is empty.
    SCHEDULING_FAILED,

    /// The seed has been read by the guest
    FETCHED,

    /// The seed path has completed
    TERMINATED
};

/// Collects global seed statistics.
/// An instance of this class is shared between all S2E instances.
struct SeedStats {
    unsigned usedSeeds;

    // This array signals to other S2E instances which other instance
    // currently has available seeds. It is used to terminate idle instances.
    bool idle[S2E_MAX_PROCESSES];

    bool getLowestIdleInstanceIndex(unsigned &index) {
        auto icnt = std::min((unsigned) S2E_MAX_PROCESSES, g_s2e->getMaxInstances());
        for (unsigned i = 0; i < icnt; ++i) {
            auto id = g_s2e->getInstanceId(i);
            if (id == -1) {
                // The process is dead, skip it.
                continue;
            }

            if (idle[i]) {
                index = i;
                return true;
            }
        }

        return false;
    }
};

///
/// \brief The SeedSearcher class implements seeding
///
/// S2E supports concolic mode, in which concrete values (aka "seeds")
/// can be used to guide path exploration. Such seeds can be obtained
/// from a fuzzer, hand-made test cases, etc.
///
/// The seed searcher plugin requires the cooperation of the guest.
/// The guest runs a script that polls the seed searcher plugin for new seeds.
/// In case there is a seed available, the guest forks a state that will
/// download the seed file from the host (using the HostFiles plugin).
/// The script must be written in such a way that the polling loop always runs
/// in state 0 (the "seed state").
///
/// \code{.sh}
/// while true; do
///   seed_file=$(./s2ecmd get_seed_file)
///   result=$?
///   if [ $result -eq 255 ]; then
///       continue
///   fi
///
///   # The loop will break out in state n, where n > 0
///   break
/// done
///
/// # This is executed in state n (n > 0)
/// if [ "x$seed_file" = "x" ]; then
///   # No seed file is available, run the program in non-concolic mode.
/// else
///   ./s2eget "$seed_file"
///   seed_file="$(basename $seed_file)"
///   # Pipe the seed file into the program
///   myprog < $seedfile
/// fi
/// \endcode
///
/// If there are no seeds available yet, SeedSearcher reverts to default
/// symbolic execution in order to avoid preventing progress.
///
/// The seed searcher does not require the seed files to be in a specific
/// format. The format solely depends on the type of program you are testing.
/// It could be a text file piped to stdin of your program, an executable file
/// to run in the guest, etc.
///
/// The seed searcher takes as input a directory containing seed files.
/// The seed file names must follow this pattern in order to be
/// recognized by the seed searcher:
///
///   <tt>&lt;seedid&gt;-&lt;priority&gt;&lt;suffix&gt;</tt>
///
/// Here are examples of valid and invalid seed names:
///
///   \li \c 0-0-mycrash.pov => seed with index 0, priority 0, and suffix mycrash.pov
///   \li \c 1-3.txt => seed with index 1, priority 3, and suffix .txt
///   \li \c abc.txt => invalid seed
///   \li \c 1-2 => seed with index 1 and priority 2, no suffix
///
/// The seed searcher periodically scans the seed directory for new seeds
/// and adds them to a priority queue. As soon as the queue contains at
/// least one seed, the searcher activates state 0 in order to fetch
/// the seed file and fork a state that will use that seed file. Other plugins
/// can modify this behavior.
///
/// The seed searcher currently collaborates with the cupa searcher
/// in order to do path exploration. When there are no seeds to explore,
/// or when the seed searcher is disabled, the seed searcher activates
/// the CUPASearcher plugin. That plugin needs to be configured
/// to filter out state 0.
///
/// <h2>Configuration Options</h2>
///
///    \li <tt><b>enableSeeds</b></tt>: enable this setting when using SeedSearcher
///        in standalone mode. Disable it to let other plugins control the behavior
///        of SeedSearcher.
///
///    \li <tt><b>maxSeedStates</b></tt>: how many seed states can be reached before
///        the searcher stops processing the seed queue. For example, if this setting
///        is 1, SeedSearcher will wait for the seed state to terminate before fetching
///        another seed. A value of 0 disables waiting.
///
class SeedSearcher : public Plugin, public klee::Searcher, public IPluginInvoker {
    S2E_PLUGIN

public:
    typedef llvm::DenseSet<unsigned> ProcessedSeeds;

    ///
    /// \brief onSeed is triggered when the searcher
    /// performs an action on a seed.
    ///
    sigc::signal<void, const Seed &, SeedEvent> onSeed;

    SeedSearcher(S2E *s2e) : Plugin(s2e) {
    }
    void initialize();

    virtual klee::ExecutionState &selectState();
    virtual void update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates);

    virtual bool empty();

private:
    typedef std::set<S2EExecutionState *> States;
    MultiSearcher *m_multiSearcher;
    CUPASearcher *m_cupa;

    sigc::connection m_timer;

    States m_states;
    Seeds m_availableSeeds;
    ProcessedSeeds m_processedSeeds;
    Seed m_currentSeed;
    bool m_selectSeedState;

    S2EExecutionState *m_cachedState;

    /// Stores the pointer to state 0
    S2EExecutionState *m_initialState;

    bool m_initialStateHasSeedFile;

    /// Stores the direct children of the initial state
    States m_seedStates;

    /// Location of the seed files
    std::string m_seedDirectory;

    /// Enables or disables seed scheduling
    bool m_enableSeeds;

    /// Stores a backup of the fetched seeds in the s2e-last/seeds folder
    bool m_backupSeeds;

    /// Location where seeds will be backed up
    std::string m_seedBackupDirectory;

    /// How many seed states are allowed concurrently
    unsigned m_maxSeedStates;

    bool m_parallelSeeds;

    unsigned m_usedSeedsCount;
    S2ESynchronizedObject<SeedStats> m_globalStats;

    void switchToCUPA();
    void switchToSeedSearcher();

    void onStateSplit(klee::StateSet &parent, klee::StateSet &child);

    void onProcessForkComplete(bool isChild);

    void onStateFork(S2EExecutionState *oldState, const std::vector<S2EExecutionState *> &newStates,
                     const std::vector<klee::ref<klee::Expr>> &);

    void onStateKill(S2EExecutionState *state);

    ///
    /// \brief Signals to other S2E instances whether or not we currently have
    /// seeds available.
    ///
    void updateIdleStatus();

    void backupSeed(const std::string &seedFilePath);
    void fetchNewSeeds();
    bool scheduleNextSeed();
    void onTimer();
    void handleGetSeedFile(S2EExecutionState *state, S2E_SEEDSEARCHER_COMMAND &cmd);

    void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);

public:
    ///
    /// \brief enableSeeds controls whether the searcher schedules seeds
    ///
    /// When seeds are disabled, the searcher will still keep polling
    /// for them and notifying clients. Clients can choose to enable seeds
    /// based on these notifications.
    ///
    /// \param enable is true to use seeds, false otherwise
    ///
    void enableSeeds(bool enable);

    /// \brief isSeedState returns whether \p state derives from a seed
    bool isSeedState(S2EExecutionState *state);

    ///
    /// \brief getSeedCount returns the number of queued seeds
    ///
    unsigned getSeedCount() const {
        return m_availableSeeds.size();
    }

    ///
    /// \brief isAvailable returns availability of the searcher on the current S2E instance
    ///
    /// Only the S2E instance that has the state 0 has the seed searcher available. Other
    /// instances cannot fetch seeds because they don't have state 0.
    ///
    /// \return the availability status
    ///
    bool isAvailable() const {
        return m_initialState != nullptr;
    }

    ///
    /// \brief getPriorityCount returns number of unique priorities in the seed queue
    ///
    unsigned getPriorityCount() const;

    ///
    /// \brief getSubtreeSeedIndex returns the index of the seed from which the given
    /// state has been derived.
    ///
    /// A seed can be seen as the skeleton, or trunk, of the execution tree. All branches
    /// derive from that trunk. This function determines which trunk a given branch belongs to.
    /// This can be useful to determine which seed has been helpful in order to
    /// find, e.g., a crash.
    ///
    /// \param state to query
    /// \return the seed index of the state
    ///
    uint64_t getSubtreeSeedIndex(S2EExecutionState *state) const;

    ///
    /// \brief getUsedSeedsCount returns how many seeds have been fetched by the guest
    ///
    /// \param global indicates whether to retrieve aggregated count across all S2E instances
    ///
    unsigned getUsedSeedsCount(bool global = false);

    ///
    /// \brief getTopPrioritySeed returns the highest priority seed
    /// \param s the returned seed
    /// \return false if there are no seeds, true otherwise
    ///
    bool getTopPrioritySeed(Seed &s) {
        return m_availableSeeds.getTopPrioritySeed(s);
    }

    ///
    /// \brief Return a copy of the shared stats structure
    ///
    void getSeedStats(SeedStats &stats);
};

} // namespace seeds
} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_SEEDSEARCHER_H
