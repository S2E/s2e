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

#include <s2e/cfg/commands.h>

#include <llvm/ADT/DenseSet.h>
#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <stack>

#include "ControlFlowGraph.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ControlFlowGraph, "Manages control flow graphs for modules", "", "ModuleExecutionDetector");

void ControlFlowGraph::initialize() {
    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();
    loadConfiguration();

    // This sets up a timer that will periodically check if the lua script
    // has updated the cfg config. If so, it will trigger a reload
    // of the control flow graph.
    s2e()->getCorePlugin()->onTimer.connect(sigc::mem_fun(*this, &ControlFlowGraph::onTimer));
}

///
/// \brief Loads the CFG from the Lua file
///
/// Sample configuration entry:
///
/// pluginsConfig.ControlFlowGraph = {
///     reloadConfig = false,
///     drv0 = {
///         functions = {
///             f0 = {pc=0x1234, name="fcnname"},...
///         },
///         basicblocks = {
///             {
///                  start_pc = 0x11945,
///                  end_pc   = 0x1194a,
///                  successors = {0x1cc5a90, },  --optional
///                  predecessors = {0x1cc5760, }, --optional
///             },
///             ....
///         }
///     },
///     drv1 = {...},
///     ...
/// }
///
/// The reloadConfig key is typically set at runtime
/// by the Lua script when it made changes to the CFG.
/// The plugin periodically polls this key, and if set
/// to true, reloads the CFG and resets the key.
///
void ControlFlowGraph::loadConfiguration() {
    ConfigFile *cfg = s2e()->getConfig();

    m_entryPoints = ModuleFunctions();
    m_basicBlocks = ModuleBasicBlocks();
    m_basicBlockCount = 0;

    ConfigFile::string_list keys = cfg->getListKeys(getConfigKey());
    /* For each configured driver (drv0...)... */
    foreach2 (it, keys.begin(), keys.end()) {
        // Ignore configuration flags
        if (*it == "reloadConfig") {
            continue;
        }

        const std::string &moduleId = *it;
        ModuleExecutionCfg moduleConfig;

        if (!m_detector->getModuleConfig(moduleId, moduleConfig)) {
            getWarningsStream() << "module id " << moduleId << " not availble in ModuleExecutionDetector\n";
            continue;
        }

        /* Get the list of function entry points */
        std::stringstream ss;
        ss << getConfigKey() << "." << moduleId;

        bool ok = false;
        unsigned functionCount = cfg->getListSize(ss.str() + ".functions", &ok);
        if (!ok) {
            getWarningsStream() << ss.str() << ".functions"
                                << " is not a valid list\n";
            exit(-1);
        }

        for (unsigned i = 0; i < functionCount; ++i) {
            std::stringstream ss1;
            ss1 << ss.str() << ".functions[" << (i + 1) << "]";
            uint64_t pc = cfg->getInt(ss1.str() + ".pc");
            std::string name = cfg->getString(ss1.str() + ".name");
            m_entryPoints[moduleConfig.moduleName][pc] = name;
        }

        /* Get the list of basic blocks */
        unsigned bbCount = cfg->getListSize(ss.str() + ".basicblocks");
        for (unsigned i = 0; i < bbCount; ++i) {
            std::stringstream ss1;
            ss1 << ss.str() << ".basicblocks[" << (i + 1) << "]";

            BasicBlock bb;
            bb.start_pc = cfg->getInt(ss1.str() + ".start_pc");
            bb.end_pc = cfg->getInt(ss1.str() + ".end_pc");
            bb.size = cfg->getInt(ss1.str() + ".size");
            bb.call_target = cfg->getInt(ss1.str() + ".call_target");

            ConfigFile::integer_list ilist;
            ilist = cfg->getIntegerList(ss1.str() + ".successors");
            bb.successors.insert(bb.successors.begin(), ilist.begin(), ilist.end());

            ilist = cfg->getIntegerList(ss1.str() + ".predecessors");
            bb.predecessors.insert(bb.predecessors.begin(), ilist.begin(), ilist.end());
            m_basicBlocks[moduleConfig.moduleName].insert(bb);
            m_basicBlockCount++;
        }
    }
}

void ControlFlowGraph::onTimer() {
    ConfigFile *cfg = s2e()->getConfig();
    bool reload = cfg->getBool(getConfigKey() + ".reloadConfig", false);
    if (reload) {
        getWarningsStream() << "Reloading configuration\n";
        loadConfiguration();
        cfg->setBool(getConfigKey() + ".reloadConfig", false);

        // Double check that setting the flag worked
        reload = cfg->getBool(getConfigKey() + ".reloadConfig", false);
        assert(reload == false && "Couldn't set reloadConfig properly");

        onReload.emit();
    }
}

bool ControlFlowGraph::isReachable(const std::string &module, uint64_t source, uint64_t dest, bool &result) const {
    ModuleBasicBlocks::const_iterator it = m_basicBlocks.find(module);
    if (it == m_basicBlocks.end()) {
        return false;
    }

    const BasicBlocks &bbs = (*it).second;
    return isReachable(bbs, source, dest, result);
}

bool ControlFlowGraph::isReachable(const BasicBlocks &bbs, uint64_t source, uint64_t dest, bool &result) const {
    /* Run DFS to see if dest may be reachable from source */
    std::stack<uint64_t> stk;
    llvm::DenseSet<uint64_t> visited;

    stk.push(source);

    while (!stk.empty()) {
        uint64_t pc = stk.top();
        stk.pop();

        const BasicBlock *bb = findBasicBlock(bbs, pc);
        if (!bb) {
            return false;
        }

        if (bb->start_pc <= dest && dest < bb->start_pc + bb->size) {
            result = true;
            return true;
        }

        if (visited.count(pc)) {
            continue;
        }

        visited.insert(pc);

        foreach2 (it, bb->successors.begin(), bb->successors.end()) {
            stk.push(*it);
        }
    }

    result = false;
    return true;
}

const ControlFlowGraph::BasicBlock *ControlFlowGraph::findBasicBlock(const std::string &module, uint64_t pc) const {
    ModuleBasicBlocks::const_iterator it = m_basicBlocks.find(module);
    if (it == m_basicBlocks.end()) {
        return nullptr;
    }

    const BasicBlocks &bbs = (*it).second;

    return findBasicBlock(bbs, pc);
}

const ControlFlowGraph::BasicBlock *ControlFlowGraph::findBasicBlock(const BasicBlocks &bbs, uint64_t pc) const {
    BasicBlock toFind;
    toFind.start_pc = pc;
    toFind.size = 1;
    BasicBlocks::const_iterator bbit = bbs.find(toFind);

    if (bbit != bbs.end()) {
        return &*bbit;
    }

    return nullptr;
}

bool ControlFlowGraph::getBasicBlockRange(const std::string &module, uint64_t start, uint64_t end,
                                          std::vector<const BasicBlock *> &blocks) {
    ModuleBasicBlocks::const_iterator it = m_basicBlocks.find(module);
    if (it == m_basicBlocks.end()) {
        return false;
    }

    const BasicBlocks &bbs = (*it).second;

    BasicBlock toFind;
    toFind.start_pc = start;
    toFind.size = 1;
    BasicBlocks::const_iterator first = bbs.lower_bound(toFind);

    toFind.start_pc = end;
    BasicBlocks::const_iterator last = bbs.upper_bound(toFind);
    BasicBlocks::const_iterator bbit;

    for (bbit = first; bbit != bbs.end() && bbit != last; ++bbit) {
        const BasicBlock *bb = &*bbit;
        blocks.push_back(bb);
    }

    return true;
}

uint64_t ControlFlowGraph::getBasicBlockCount(const std::string &module) const {
    ModuleBasicBlocks::const_iterator it = m_basicBlocks.find(module);
    if (it == m_basicBlocks.end()) {
        return 0;
    }

    const BasicBlocks &bbs = (*it).second;
    return bbs.size();
}

bool ControlFlowGraph::getFinalSuccessor(const std::string &module, uint64_t start, uint64_t *end) const {
    ModuleBasicBlocks::const_iterator it = m_basicBlocks.find(module);
    if (it == m_basicBlocks.end()) {
        return false;
    }

    const BasicBlocks &bbs = (*it).second;
    uint64_t savedStart = start;

    do {
        const BasicBlock *bb = findBasicBlock(bbs, start);
        if (bb->successors.size() != 1) {
            *end = bb->start_pc;
            return true;
        } else {
            start = *bb->successors.begin();
        }
        if (start == savedStart) {
            // We have an infinite loop
            return false;
        }

    } while (true);

    pabort("Can't get here");
    return false;
}

bool ControlFlowGraph::getFunctionName(const std::string &module, uint64_t entry_point, std::string &name) const {
    ModuleFunctions::const_iterator it = m_entryPoints.find(module);
    if (it == m_entryPoints.end()) {
        return false;
    }

    const FunctionEntryPoints &bbs = (*it).second;
    FunctionEntryPoints::const_iterator fit = bbs.find(entry_point);
    if (fit == bbs.end()) {
        return false;
    }

    name = (*fit).second;
    return true;
}

void ControlFlowGraph::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
    S2E_CFG_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_CFG_COMMAND size\n";
        return;
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "could not read transmitted data\n";
        return;
    }

    switch (command.Command) {
        case CFG_REGISTER_FUNCTION: {
            auto desc = m_detector->getModule(state, command.Function.RunTimeFunctionAddress);
            if (!desc) {
                getWarningsStream(state) << "could not resolve module for address "
                                         << hexval(command.Function.RunTimeFunctionAddress) << "\n";
                break;
            }

            std::string FunctionName;
            if (!state->mem()->readString(command.Function.FunctionName, FunctionName)) {
                getWarningsStream(state) << "could not read name for function "
                                         << hexval(command.Function.RunTimeFunctionAddress) << "\n";
                break;
            }

            uint64_t RelFunctionPc;
            if (!desc->ToNativeBase(command.Function.RunTimeFunctionAddress, RelFunctionPc)) {
                getWarningsStream(state) << "Could not translate " << hexval(command.Function.RunTimeFunctionAddress)
                                         << "\n";
                return;
            }
            m_entryPoints[desc->Name][RelFunctionPc] = FunctionName;

            getInfoStream(state) << "Registered function " << desc->Name << ":" << hexval(RelFunctionPc) << "("
                                 << FunctionName << ")\n";
        } break;

        default:
            getWarningsStream(state) << "unknown command " << command.Command << "\n";
    }
}

} // namespace plugins
} // namespace s2e
