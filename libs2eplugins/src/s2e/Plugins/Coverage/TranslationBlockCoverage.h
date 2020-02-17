///
/// Copyright (C) 2016, Cyberhaven
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

#ifndef S2E_PLUGINS_TranslationBlockCoverage_H
#define S2E_PLUGINS_TranslationBlockCoverage_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Synchronization.h>

#include <klee/Internal/ADT/ImmutableSet.h>

#include <unordered_map>

namespace s2e {
namespace plugins {
namespace coverage {

struct TB {
    uint64_t startPc;
    uint64_t lastPc;
    uint32_t size;
    uint32_t startOffset;

    bool operator<(const TB &a) const {
        // Don't allow overlapping TBs because this
        // causes many redundant blocks in the set.
        return startPc + size <= a.lastPc;
    }
};

// Use an immutable set to share as much information between the states.
// This also avoids costly copying when forking.
typedef klee::ImmutableSet<TB> TBs;
typedef std::unordered_map<std::string, TBs> ModuleTBs;

///
/// \brief mergeCoverage merges into dest translation blocks in source
/// \param dest the destination where to merge
/// \param source the blocks to merge into dest
/// \return true if source contains blocks not present in dest
///
bool mergeCoverage(ModuleTBs &dest, const ModuleTBs &source);

///
/// \brief The Bitmap class represents the coverage status
/// of each byte of every binary.
///
/// It can hold up to 10 binaries of 8 MB each. The maximum size
/// is hardcoded in order to easily share this information
/// between multiple S2E instances through shared memory.
///
/// Notes:
///   - It is up to the caller to assign an index to each module
///
class Bitmap {
    static const unsigned MAX_MODULES = 10;
    static const unsigned MAX_MODULE_BYTES = 8 * 1024 * 1024;
    uint8_t coverage[MAX_MODULES][MAX_MODULE_BYTES / 8];

public:
    inline bool isCovered(unsigned module, unsigned offset, bool &covered) const {
        if (module >= MAX_MODULES || offset >= MAX_MODULE_BYTES) {
            return false;
        }

        covered = (coverage[module][offset / 8] & (1 << (offset % 8))) != 0;
        return true;
    }

    inline bool setCovered(unsigned module, unsigned offset) {
        if (module >= MAX_MODULES || offset >= MAX_MODULE_BYTES) {
            return false;
        }

        coverage[module][offset / 8] |= (1 << (offset % 8));
        return true;
    }

    ///
    /// \brief setCovered covers the given module range
    /// \param module module index to cover
    /// \param start first byte of the range to cover
    /// \param count how many bytes to cover
    /// \param covered true if the range was already (partly) covered
    /// \return false if coverage info could not be set
    ///
    inline bool setCovered(unsigned module, unsigned start, unsigned count, bool &covered) {
        covered = false;
        bool success = true;
        for (unsigned i = 0; i < count; ++i) {
            success &= isCovered(module, start + i, covered);
            success &= setCovered(module, start + i);
        }
        return success;
    }
};

typedef S2ESynchronizedObject<Bitmap> GlobalCoverage;

class TranslationBlockCoverage : public Plugin {
    S2E_PLUGIN
public:
    ///
    /// \brief onNewBlockCovered is emitted when a translation block
    /// covering new code is generated. This event takes into account
    /// coverage across all S2E instances.
    ///
    sigc::signal<void, S2EExecutionState *> onNewBlockCovered;

    TranslationBlockCoverage(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    const ModuleTBs &getCoverage(S2EExecutionState *state);

    std::string generateJsonCoverageFile(S2EExecutionState *state);
    void generateJsonCoverageFile(S2EExecutionState *state, const std::string &filePath);
    void generateJsonCoverage(S2EExecutionState *state, std::stringstream &ss);

    ///
    /// \brief getStatesWithNewBlocks returns states that found new translation blocks
    ///
    /// Notes:
    ///    - A state may be deleted from the set if it is killed. It is up to the
    ///      caller to hook onStateKill and retrieve coverage from there.
    ///      Failing to do so may result in underreported coverage info.
    ///
    ///    - This does not keep track of coverage across S2E instances.
    ///      Clients must do further filtering to avoid overreporting coverage.
    ///
    /// \return the set of states
    ///
    const klee::StateSet &getStatesWithNewBlocks() const {
        return m_newBlockStates;
    }

    ///
    /// \brief clearStatesWithNewBlocks resets global coverage for all states
    ///
    /// This is useful to call after getStatesWithNewBlocks to get incremental
    /// information.
    ///
    /// Notes:
    ///    - Per-state covered blocks are not deleted. A call to getCoverage()
    ///      will still return the complete set of translation blocks for
    ///      a given state.
    ///
    void clearStatesWithNewBlocks() {
        m_newBlockStates.clear();
    }

private:
    ModuleExecutionDetector *m_detector;

    klee::StateSet m_newBlockStates;
    ModuleTBs m_localCoverage;
    GlobalCoverage m_globalCoverage;
    unsigned m_writeCoveragePeriod;
    unsigned m_timerTicks;

    void onTimer();
    void onStateKill(S2EExecutionState *state);
    void onStateSwitch(S2EExecutionState *current, S2EExecutionState *next);
    void onModuleTranslateBlockComplete(S2EExecutionState *state, const ModuleDescriptor &module, TranslationBlock *tb,
                                        uint64_t last_pc);

    void onUpdateStates(S2EExecutionState *currentState, const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates);
};

} // namespace coverage
} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_TranslationBlockCoverage_H
