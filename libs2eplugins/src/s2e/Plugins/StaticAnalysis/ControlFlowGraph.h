///
/// Copyright (C) 2013-2015, Dependable Systems Laboratory, EPFL
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

#ifndef S2E_PLUGINS_ControlFlowGraph_H
#define S2E_PLUGINS_ControlFlowGraph_H

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/DenseSet.h>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {
namespace plugins {

///
/// \brief The ControlFlowGraph class represents a CFG
///
class ControlFlowGraph : public Plugin, public IPluginInvoker {
    S2E_PLUGIN
public:
    ControlFlowGraph(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    typedef llvm::SmallVector<uint64_t, 2> ProgramCounters;

    // Maps a function entry block to a function name
    typedef llvm::DenseMap<uint64_t, std::string> FunctionEntryPoints;

    struct BasicBlock {
        uint64_t start_pc;
        uint64_t end_pc;
        unsigned size;
        uint64_t call_target;
        ProgramCounters successors;
        ProgramCounters predecessors;

        BasicBlock() {
            start_pc = end_pc = 0;
            size = 0;
        }

        // TODO: take into account the size
        bool operator<(const BasicBlock &bb) const {
            return start_pc + size <= bb.start_pc;
        }
    };

    typedef std::set<BasicBlock> BasicBlocks;
    typedef std::map<std::string, BasicBlocks> ModuleBasicBlocks;

    typedef std::map<std::string, FunctionEntryPoints> ModuleFunctions;

    sigc::signal<void> onReload;

    const BasicBlock *findBasicBlock(const std::string &module, uint64_t pc) const;

    bool getBasicBlockRange(const std::string &module, uint64_t start, uint64_t end,
                            std::vector<const BasicBlock *> &blocks);

    uint64_t getBasicBlockCount(const std::string &module) const;
    uint64_t getBasicBlockCount() const {
        return m_basicBlockCount;
    }

    /**
     * Follows a chain of basic blocks linked together by direct jumps.
     * Return the pc of the first basic block that has multiple targets.
     */
    bool getFinalSuccessor(const std::string &module, uint64_t start, uint64_t *end) const;

    bool getFunctionName(const std::string &module, uint64_t entry_point, std::string &name) const;

    bool isReachable(const std::string &module, uint64_t source, uint64_t dest, bool &result) const;
    bool isReachable(const BasicBlocks &bbs, uint64_t source, uint64_t dest, bool &result) const;

private:
    ModuleExecutionDetector *m_detector;
    ModuleFunctions m_entryPoints;
    ModuleBasicBlocks m_basicBlocks;

    uint64_t m_basicBlockCount;

    void loadConfiguration();
    const BasicBlock *findBasicBlock(const BasicBlocks &bbs, uint64_t pc) const;

    void onTimer();

    /* Guest config interface */
    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_ControlFlowGraph_H
