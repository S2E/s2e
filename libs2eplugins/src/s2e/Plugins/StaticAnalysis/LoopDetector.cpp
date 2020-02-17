///
/// Copyright (C) 2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014, Cyberhaven
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

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <iostream>

#include "LoopDetector.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LoopDetector, "LoopDetector S2E plugin", "", "EdgeDetector", "ModuleExecutionDetector",
                  "ControlFlowGraph");

void LoopDetector::initialize() {
    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();
    m_edgeDetector = s2e()->getPlugin<EdgeDetector>();
    m_cfg = s2e()->getPlugin<ControlFlowGraph>();

    /**
     * Sample configuration entry:
     *
     * pluginsConfig.LoopDetector = {
     *     drv0 = {
     *         l0 = {
     *             header = 0x19237
     *             backedges = {{0x1934b, 0x19237}, ...},
     *             exitblocks = {0x19350, ... },
     *             basicblocks = {0x19350, ... },
     *         },
     *         ...
     *     },
     *     drv1 = {},
     *     ...
     */

    ConfigFile *cfg = s2e()->getConfig();

    ConfigFile::string_list keys = cfg->getListKeys(getConfigKey());
    /* For each configured driver (drv0...)... */
    foreach2 (it, keys.begin(), keys.end()) {
        const std::string &moduleId = *it;
        ModuleExecutionCfg moduleConfig;

        if (!m_detector->getModuleConfig(moduleId, moduleConfig)) {
            getWarningsStream() << "LoopDetector: "
                                << "module id " << moduleId << " not availble in ModuleExecutionDetector\n";
            continue;
        }

        /* For each loop descriptor... */
        std::stringstream ss;
        ss << getConfigKey() << "." << moduleId;
        ConfigFile::string_list loop_keys = cfg->getListKeys(ss.str());
        foreach2 (eit, loop_keys.begin(), loop_keys.end()) {
            const std::string loop_key = *eit;
            std::stringstream ss1;
            ss1 << ss.str() << "." << loop_key;

            /* Get the header block */
            uint64_t header = cfg->getInt(ss1.str() + ".header");
            m_headers[moduleConfig.moduleName].insert(header);

            /* Get the backedge (list of list of two integers) */
            unsigned backedgeCount = cfg->getListSize(ss1.str() + ".backedges");
            for (unsigned i = 0; i < backedgeCount; ++i) {
                std::stringstream ss2;
                ss2 << ss1.str() << ".backedges[" << (i + 1) << "]";
                ConfigFile::integer_list backedge = cfg->getIntegerList(ss2.str());
                if (backedge.size() != 2) {
                    getWarningsStream() << "EdgeDetector entry " << ss1.str()
                                        << " must be of the form {sourcePc, destPc}\n";
                    continue;
                }
                /* Store all this stuff in the data structures */
                m_edgeDetector->addEdge(moduleConfig.moduleName, backedge[0], backedge[1], EDGE_LOOP_BACKEDGE);
            }

            /* Get the exit edges (list of list of two integers) */
            unsigned exitedgeCount = cfg->getListSize(ss1.str() + ".exitedges");
            for (unsigned i = 0; i < exitedgeCount; ++i) {
                std::stringstream ss2;
                ss2 << ss1.str() << ".exitedges[" << (i + 1) << "]";
                ConfigFile::integer_list exitedge = cfg->getIntegerList(ss2.str());
                if (exitedge.size() != 2) {
                    getWarningsStream() << "EdgeDetector entry " << ss1.str()
                                        << " must be of the form {sourcePc, destPc}\n";
                    continue;
                }
                /* Store all this stuff in the data structures */
                m_edgeDetector->addEdge(moduleConfig.moduleName, exitedge[0], exitedge[1], EDGE_LOOP_EXIT);
            }

            /* Get the list of exit blocks */
            ConfigFile::integer_list exitblocks = cfg->getIntegerList(ss1.str() + ".exitblocks");
            m_exitBlocks[moduleConfig.moduleName].insert(exitblocks.begin(), exitblocks.end());

            /* Get the list of basic blocks */
            ConfigFile::integer_list basicblocks = cfg->getIntegerList(ss1.str() + ".basicblocks");

            foreach2 (bbit, basicblocks.begin(), basicblocks.end()) {
                m_basicBlocks[moduleConfig.moduleName][*bbit] = header;
            }
        }
    }

    if (m_headers.size() > 0 || m_exitBlocks.size() > 0) {
        m_detector->onModuleTranslateBlockStart.connect(
            sigc::mem_fun(*this, &LoopDetector::onModuleTranslateBlockStart));

        m_edgeDetector->onEdge.connect(sigc::mem_fun(*this, &LoopDetector::onEdge));
    }
}

//////////////////////////////////////////////////////
// XXX: most of this stuff is from EdgeDetector and
// seems to be a common pattern for S2E plugins. Might want
// to make it generic.
void LoopDetector::onModuleTransition(S2EExecutionState *state, const ModuleDescriptor *prevModule,
                                      const ModuleDescriptor *nextModule) {
    /**
     * This handles the case when an exception that is thrown during translation.
     * We don't want the signals to be attached for code outside of the module.
     */
    m_ins_connection.disconnect();
    m_mod_connection.disconnect();
}

void LoopDetector::onModuleTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state,
                                               const ModuleDescriptor &module, TranslationBlock *tb, uint64_t pc) {
    /* Disconnect any stale handlers */
    m_ins_connection.disconnect();
    m_mod_connection.disconnect();

    /* Check if we have edges that belong to this module. */
    ModuleLoopHeaders::iterator hit = m_headers.find(module.Name);
    ModuleLoopExitBlocks::iterator eit = m_exitBlocks.find(module.Name);
    if (eit == m_exitBlocks.end() && hit == m_headers.end()) {
        return;
    }

    m_ins_connection = s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
        sigc::bind(sigc::mem_fun(*this, &LoopDetector::onTranslateInstructionEnd),
                   (-module.LoadBase + module.NativeBase) /* Pass an addend to convert the program counter */,
                   &(*hit).second, &(*eit).second));

    m_mod_connection = m_detector->onModuleTranslateBlockComplete.connect(
        sigc::mem_fun(*this, &LoopDetector::onModuleTranslateBlockComplete));
}

/**
 * The notification must be done *after* the first instruction of the block executed successfully.
 * If we do it before the instruction, there may be multiple spurious events if
 * the instruction is aborted (exception, etc.).
 */
void LoopDetector::onTranslateInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                             uint64_t pc, uint64_t addend, LoopHeaders *_headers,
                                             LoopExitBlocks *_exitblocks) {
    uint64_t modulePc = pc + addend;

    /* Note: the exit block of a loop can be the header of another one */
    LoopHeaders::iterator hit = (*_headers).find(modulePc);
    if (hit != _headers->end()) {
        // getDebugStream(state) << "LoopDetector: translation detected header block at " << hexval(modulePc) << "\n";
        signal->connect(sigc::mem_fun(*this, &LoopDetector::onLoopHeader));
    }
}

void LoopDetector::onLoopHeader(S2EExecutionState *state, uint64_t sourcePc) {
    // getDebugStream(state) << "LoopDetector: executing loop header at " << hexval(sourcePc) << "\n";
    onLoop.emit(state, sourcePc, LOOP_HEADER);
}

void LoopDetector::onLoopExit(S2EExecutionState *state, uint64_t sourcePc) {
    // getDebugStream(state) << "LoopDetector: executing loop exit at " << hexval(sourcePc) << "\n";
    // onLoop.emit(state, sourcePc, LOOP_EXIT);
}

void LoopDetector::onEdge(S2EExecutionState *state, uint64_t sourcePc, EdgeType type) {
    if (type == EDGE_LOOP_BACKEDGE) {
        onLoop.emit(state, sourcePc, LOOP_BACKEDGE);
    } else if (type == EDGE_LOOP_EXIT) {
        onLoop.emit(state, sourcePc, LOOP_EXITEDGE);
    }
}

void LoopDetector::onModuleTranslateBlockComplete(S2EExecutionState *state, const ModuleDescriptor &module,
                                                  TranslationBlock *tb, uint64_t endPc) {
    m_ins_connection.disconnect();
    m_mod_connection.disconnect();
}

} // namespace plugins
} // namespace s2e
