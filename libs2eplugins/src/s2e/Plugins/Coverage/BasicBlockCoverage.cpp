///
/// Copyright (C) 2013-2015, Dependable Systems Laboratory, EPFL
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

#include <s2e/cpu.h>

#include <qapi/qmp/qdict.h>
#include <qapi/qmp/qjson.h>
#include <qapi/qmp/qlist.h>

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/Core/Events.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <s2e/S2EStatsTracker.h>

#include "BasicBlockCoverage.h"

namespace s2e {
namespace plugins {
namespace coverage {

S2E_DEFINE_PLUGIN(BasicBlockCoverage, "Reports basic block coverage for registered modules", "", "ControlFlowGraph");

namespace {

struct BasicBlockCoverageState : public PluginState {
    BasicBlockCoverage::ModuleBasicBlocks coverage;

    static PluginState *factory(Plugin *p, S2EExecutionState *) {
        return new BasicBlockCoverageState();
    }

    virtual BasicBlockCoverageState *clone() const {
        return new BasicBlockCoverageState(*this);
    }
};
} // namespace

void BasicBlockCoverage::initialize() {
    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();
    m_cfg = s2e()->getPlugin<ControlFlowGraph>();

    m_detector->onModuleTranslateBlockComplete.connect(
        sigc::mem_fun(*this, &BasicBlockCoverage::onModuleTranslateBlockComplete));

    s2e()->getCorePlugin()->onTimer.connect(sigc::mem_fun(*this, &BasicBlockCoverage::onTimer));

    s2e()->getCorePlugin()->onUpdateStates.connect(sigc::mem_fun(*this, &BasicBlockCoverage::onUpdateStates));

    m_cfg->onReload.connect(sigc::mem_fun(*this, &BasicBlockCoverage::onCfgReload));

    ConfigFile *cfg = s2e()->getConfig();

    // This is mainly for debugging, in normal use would generate too many files
    bool writeCoverageOnStateKill = cfg->getBool(getConfigKey() + ".writeCoverageOnStateKill");
    if (writeCoverageOnStateKill) {
        s2e()->getCorePlugin()->onStateKill.connect(sigc::mem_fun(*this, &BasicBlockCoverage::onStateKill));
    }
}

void BasicBlockCoverage::onCfgReload() {
    // This is important so that basic block coverage
    // can catch onTranslateBlockComplete event for already
    // translated blocks.
    se_tb_safe_flush();
}

void BasicBlockCoverage::onStateKill(S2EExecutionState *state) {
    generateJsonCoverageFile(state);
}

void BasicBlockCoverage::onUpdateStates(S2EExecutionState *state, const klee::StateSet &addedStates,
                                        const klee::StateSet &removedStates) {
    foreach2 (it, removedStates.begin(), removedStates.end()) {
        S2EExecutionState *state = static_cast<S2EExecutionState *>(*it);
        // XXX: avoid the loop
        foreach2 (mit, m_nonCoveredBasicBlocks.begin(), m_nonCoveredBasicBlocks.end()) {
            MultiStatesBB &bbs = (*mit).second;
            StatesByPointer &byptr = bbs.get<state_t>();
            byptr.erase(state);
        }
    }
}

void BasicBlockCoverage::addNonCoveredBlock(S2EExecutionState *state, const std::string &module, uint64_t block) {
    if (isCovered(module, block)) {
        return;
    }

    // XXX: check if it's really a bb start
    StateBB info;
    info.pc = block;
    info.state = state;
    m_nonCoveredBasicBlocks[module].insert(info);
}

void BasicBlockCoverage::printNonCoveredBlocks() {
    foreach2 (it, m_nonCoveredBasicBlocks.begin(), m_nonCoveredBasicBlocks.end()) {
        llvm::DenseMap<uint64_t, unsigned> blocks;
        const std::string &module = (*it).first;

        MultiStatesBB &bbs = (*it).second;
        StatesByPc &bypc = bbs.get<pc_t>();

        foreach2 (bit, bypc.begin(), bypc.end()) {
            blocks[(*bit).pc]++;
        }

        foreach2 (it, blocks.begin(), blocks.end()) {
            getDebugStream() << "BasicBlockCoverage: block " << module << "!" << hexval((*it).first)
                             << " not covered in " << (*it).second << " states\n";
        }
    }
}

std::string BasicBlockCoverage::generateJsonCoverageFile(S2EExecutionState *state) {
    std::string path;

    std::stringstream fileName;
    fileName << "coverage-" << state->getID() << ".json";
    path = s2e()->getOutputFilename(fileName.str());

    generateJsonCoverageFile(state, path);

    return path;
}

void BasicBlockCoverage::generateJsonCoverageFile(S2EExecutionState *state, const std::string &path) {
    std::stringstream coverage;
    generateJsonCoverage(state, coverage);

    std::ofstream o(path.c_str());
    o << coverage.str();
    o.close();
}

void BasicBlockCoverage::generateJsonCoverage(S2EExecutionState *state, std::stringstream &coverage) {
    QDict *pt = qdict_new();

    const ModuleBasicBlocks &bbs = getCoverage(state);
    foreach2 (it, bbs.begin(), bbs.end()) {
        auto module = *it;

        QList *blocks = qlist_new();
        foreach2 (pcit, module.second.begin(), module.second.end()) {
            auto bb = m_cfg->findBasicBlock(module.first, *pcit);
            if (!bb) {
                continue;
            }

            std::string fcnName;
            bool isFcnEntryPoint = m_cfg->getFunctionName(module.first, bb->start_pc, fcnName);

            QList *info = qlist_new();
            qlist_append_obj(info, QOBJECT(qnum_from_int(bb->start_pc)));
            qlist_append_obj(info, QOBJECT(qnum_from_int(bb->end_pc)));
            qlist_append_obj(info, QOBJECT(qnum_from_int(isFcnEntryPoint)));

            qlist_append_obj(blocks, QOBJECT(info));
        }

        uint64_t bbcount = m_cfg->getBasicBlockCount(module.first);

        QDict *modInfo = qdict_new();
        qdict_put_obj(modInfo, "static_bbs", QOBJECT(qnum_from_int(bbcount)));
        qdict_put_obj(modInfo, "covered_blocks", QOBJECT(blocks));

        qdict_put_obj(pt, module.first.c_str(), QOBJECT(modInfo));
    }

    auto json = qobject_to_json(QOBJECT(pt));
    coverage << json->str << "\n";
    g_string_free(json, true);

    qobject_unref(pt);
}

S2EExecutionState *BasicBlockCoverage::getNonCoveredState(llvm::DenseSet<S2EExecutionState *> &filter) {
    foreach2 (it, m_nonCoveredBasicBlocks.begin(), m_nonCoveredBasicBlocks.end()) {
        MultiStatesBB &bbs = (*it).second;
        StatesByPc &bypc = bbs.get<pc_t>();

        foreach2 (bit, bypc.begin(), bypc.end()) {
            S2EExecutionState *state = (*bit).state;
            if (filter.find(state) != filter.end()) {
                getDebugStream() << "BasicBlockCoverage: "
                                 << "State id " << (*bit).state->getID() << " has not covered bb " << hexval((*bit).pc)
                                 << " yet\n";
                return (*bit).state;
            }
        }
    }

    return nullptr;
}

void BasicBlockCoverage::onModuleTranslateBlockComplete(S2EExecutionState *state, const ModuleDescriptor &module,
                                                        TranslationBlock *tb, uint64_t last_pc) {
    uint64_t start_pc;
    if (!module.ToNativeBase(tb->pc, start_pc)) {
        return;
    }

    uint64_t end_pc = start_pc + tb->size - 1;

    std::vector<const ControlFlowGraph::BasicBlock *> blocks;
    m_cfg->getBasicBlockRange(module.Name, start_pc, end_pc, blocks);

    if (blocks.size() == 0) {
        return;
    }

    CoveredBlocks &moduleBlocks = m_coveredBlocks[module.Name];

    // getDebugStream(state) << "BasicBlockCoverage for tb " << hexval(start_pc) << " "
    //        << hexval(end_pc) << "\n";

    StateLocations::iterator cit = m_nonCoveredBasicBlocks.find(module.Name);

    DECLARE_PLUGINSTATE(BasicBlockCoverageState, state);

    BasicBlockCoverage::BasicBlocks BBs = plgState->coverage[module.Name];

    unsigned newBlocks = 0;
    bool hasUncoveredBlocks = false;
    foreach2 (it, blocks.begin(), blocks.end()) {
        BBs = BBs.insert((*it)->start_pc);

        if (moduleBlocks.find((*it)->start_pc) == moduleBlocks.end()) {
            hasUncoveredBlocks = true;
            moduleBlocks.insert((*it)->start_pc);
            ++newBlocks;

            // Erase all the states that forked to the newly covered bb
            if (cit != m_nonCoveredBasicBlocks.end()) {
                MultiStatesBB &bbs = (*cit).second;
                StatesByPc &bypc = bbs.get<pc_t>();
                bypc.erase((*it)->start_pc);
            }
        }
    }

    plgState->coverage[module.Name] = BBs;

    // Assume that a translated block is going to be executed anyway
    if (hasUncoveredBlocks) {
        onNewBlockCovered.emit(state);
    }
}

const BasicBlockCoverage::ModuleBasicBlocks &BasicBlockCoverage::getCoverage(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(BasicBlockCoverageState, state);
    return plgState->coverage;
}

void BasicBlockCoverage::onTimer() {

    foreach2 (it, m_coveredBlocks.begin(), m_coveredBlocks.end()) {
        const std::string &module = (*it).first;
        const CoveredBlocks &blocks = (*it).second;

        uint64_t total = m_cfg->getBasicBlockCount(module);
        uint64_t covered = blocks.size();

        getDebugStream() << "BasicBlockCoverage: " << module << " covered " << covered << "/" << total << " ("
                         << (covered * 100 / total) << "%)\n";
    }
}

} // namespace coverage
} // namespace plugins
} // namespace s2e
