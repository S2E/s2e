///
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

#ifndef S2E_PLUGINS_LoopDetector_H
#define S2E_PLUGINS_LoopDetector_H

#include <llvm/ADT/DenseSet.h>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/S2EExecutionState.h>
#include "ControlFlowGraph.h"
#include "EdgeDetector.h"

namespace s2e {
namespace plugins {

class LoopDetector : public Plugin {
    S2E_PLUGIN
public:
    LoopDetector(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    enum LoopEventType {
        LOOP_HEADER, // XXX: this signal might be redundant with entry and exit.
        LOOP_ENTRY,
        LOOP_EXITEDGE,
        LOOP_BACKEDGE
    };

    sigc::signal<void, S2EExecutionState *, uint64_t /* source pc */, LoopEventType> onLoop;

    /**
     * Determines whether the given basic block belongs to a loop.
     */
    bool inLoop(const std::string &moduleName, uint64_t bb_start) {
        uint64_t header;
        return getLoop(moduleName, bb_start, header);
    }

    bool getLoop(const std::string &moduleName, uint64_t bb, uint64_t &header) {
        ModuleLoopBasicBlocks::iterator it = m_basicBlocks.find(moduleName);
        if (it == m_basicBlocks.end()) {
            return false;
        }

        LoopBasicBlocks::iterator lit = (*it).second.find(bb);

        if (lit == (*it).second.end()) {
            return false;
        }

        header = (*lit).second;
        return true;
    }

    /**
     * Determines whether the given basic block belongs to a specific loop.
     */
    bool inLoop(const std::string &moduleName, uint64_t header, uint64_t bb_start) {
        ModuleLoopBasicBlocks::iterator it = m_basicBlocks.find(moduleName);
        if (it == m_basicBlocks.end()) {
            return false;
        }

        LoopBasicBlocks::iterator lit = (*it).second.find(bb_start);
        if (lit == (*it).second.end()) {
            return false;
        }

        return (*lit).second == header;
    }

    bool isBackEdge(const std::string &moduleName, uint64_t start, uint64_t end) {
        EdgeType result;
        if (!m_edgeDetector->findEdge(moduleName, start, end, &result)) {
            return false;
        }
        return result == EDGE_LOOP_BACKEDGE;
    }

    bool isExitBlock(const std::string &moduleName, uint64_t bb_start) {
        ModuleLoopExitBlocks::iterator it = m_exitBlocks.find(moduleName);
        if (it == m_exitBlocks.end()) {
            return false;
        }

        return ((*it).second.find(bb_start) != (*it).second.end());
    }

    struct LoopInfo {
        /* Symbolic variables that were created in the loop */
        std::set<std::string> symbValNames;
        bool isPollingLoop;

        LoopInfo() {
            isPollingLoop = false;
        }
    };

    void setLoopInfo(const std::string &moduleName, uint64_t header, const LoopInfo &li) {
        m_loopInfo[moduleName][header] = li;
    }

    LoopInfo &getLoopInfo(const std::string &moduleName, uint64_t header) {
        return m_loopInfo[moduleName][header];
    }

private:
    typedef llvm::DenseSet<uint64_t> LoopExitBlocks;
    typedef llvm::DenseSet<uint64_t> LoopHeaders;

    /* Maps a basic block to a loop header */
    typedef llvm::DenseMap<uint64_t, uint64_t> LoopBasicBlocks;

    /* Maps a loop header to a boolean indicating whether the loop creates symb vals */
    typedef llvm::DenseMap<uint64_t, LoopInfo> LoopInfoMap;

    typedef std::map<std::string, LoopHeaders> ModuleLoopHeaders;
    typedef std::map<std::string, LoopExitBlocks> ModuleLoopExitBlocks;
    typedef std::map<std::string, LoopBasicBlocks> ModuleLoopBasicBlocks;
    typedef std::map<std::string, LoopInfoMap> ModuleLoopInfoMap;

    ModuleExecutionDetector *m_detector;
    EdgeDetector *m_edgeDetector;
    ControlFlowGraph *m_cfg;

    sigc::connection m_ins_connection;
    sigc::connection m_mod_connection;

    ModuleLoopHeaders m_headers;
    ModuleLoopExitBlocks m_exitBlocks;
    ModuleLoopBasicBlocks m_basicBlocks;
    ModuleLoopInfoMap m_loopInfo;

    void onModuleTransition(S2EExecutionState *state, const ModuleDescriptor *prevModule,
                            const ModuleDescriptor *nextModule);

    void onModuleTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, const ModuleDescriptor &module,
                                     TranslationBlock *tb, uint64_t pc);

    void onTranslateInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc,
                                   uint64_t addend, LoopHeaders *_headers, LoopExitBlocks *_exitblocks);

    void onModuleTranslateBlockComplete(S2EExecutionState *state, const ModuleDescriptor &module, TranslationBlock *tb,
                                        uint64_t endPc);

    void onLoopHeader(S2EExecutionState *state, uint64_t sourcePc);
    void onLoopExit(S2EExecutionState *state, uint64_t sourcePc);
    void onEdge(S2EExecutionState *state, uint64_t sourcePc, EdgeType type);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_LoopDetector_H
