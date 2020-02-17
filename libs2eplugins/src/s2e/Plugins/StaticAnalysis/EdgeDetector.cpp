///
/// Copyright (C) 2013-2015, Dependable Systems Laboratory, EPFL
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

#include <llvm/Support/CommandLine.h>
#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include <sstream>

#include "EdgeDetector.h"

namespace s2e {
namespace plugins {

namespace {
// XXX: should go in the config file
llvm::cl::opt<bool> DebugEdgeDetector("s2e-debug-edge-detector", llvm::cl::init(false));
} // namespace

S2E_DEFINE_PLUGIN(EdgeDetector, "Fires an event when a specified sequence of instructions has been executed",
                  "EdgeDetector", "ModuleExecutionDetector");

void EdgeDetector::initialize() {
    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();

    readConfig(getConfigKey(), this);

    m_detector->onModuleTranslateBlockStart.connect(sigc::mem_fun(*this, &EdgeDetector::onModuleTranslateBlockStart));

    m_detector->onModuleTransition.connect(sigc::mem_fun(*this, &EdgeDetector::onModuleTransition));
}

void EdgeDetector::readConfig(const std::string &configKey, IEdgeAdder *adder) {
    ConfigFile *cfg = s2e()->getConfig();

    ConfigFile::string_list keys = cfg->getListKeys(configKey);
    foreach2 (it, keys.begin(), keys.end()) {
        const std::string &moduleId = *it;
        ModuleExecutionCfg moduleConfig;

        if (!m_detector->getModuleConfig(moduleId, moduleConfig)) {
            getWarningsStream() << "EdgeDetector: "
                                << "module id " << moduleId << " not availble in ModuleExecutionDetector\n";
            continue;
        }

        std::stringstream ss;
        ss << configKey << "." << moduleId;
        ConfigFile::string_list edge_keys = cfg->getListKeys(ss.str());
        foreach2 (eit, edge_keys.begin(), edge_keys.end()) {
            const std::string edge_key = *eit;
            std::stringstream ss1;
            ss1 << ss.str() << "." << edge_key;

            ConfigFile::integer_list il = cfg->getIntegerList(ss1.str());
            if (il.size() != 2) {
                getWarningsStream() << "EdgeDetector entry " << ss1.str()
                                    << " must be of the form {sourcePc, destPc}\n";
                continue;
            }

            getDebugStream() << "EdgeDetector: " << moduleConfig.moduleName << ": " << hexval(il[0]) << " => "
                             << hexval(il[1]) << "\n";

            adder->addEdge(moduleConfig.moduleName, il[0], il[1], EDGE_NONE);
        }
    }
}

void EdgeCollection::addEdge(const std::string &moduleName, uint64_t start, uint64_t end, EdgeType type) {
    m_edges[moduleName][start].push_back(EdgeTargetType(end, type));
}

bool EdgeCollection::findEdge(const std::string &moduleName, uint64_t start, uint64_t end, EdgeType *result) {
    ModuleEdges::iterator it = m_edges.find(moduleName);
    if (it == m_edges.end()) {
        return false;
    }

    Edges &edges = (*it).second;
    Edges::iterator eit = edges.find(start);
    if (eit == edges.end()) {
        return false;
    }

    EdgeTargets &targets = (*eit).second;

    foreach2 (tit, targets.begin(), targets.end()) {
        if ((*tit).first == end) {
            *result = (*tit).second;
            return true;
        }
    }

    return false;
}

void EdgeDetector::addEdge(const std::string &moduleName, uint64_t start, uint64_t end, EdgeType type) {
    getDebugStream() << "EdgeDetector: adding edge " << moduleName << " " << hexval(start) << " => " << hexval(end)
                     << " type:" << type << "\n";
    m_edges.addEdge(moduleName, start, end, type);
}

bool EdgeDetector::findEdge(const std::string &moduleName, uint64_t start, uint64_t end, EdgeType *result) {
    return m_edges.findEdge(moduleName, start, end, result);
}

//////////////////////////////////////////////////////
void EdgeDetector::onModuleTransition(S2EExecutionState *state, ModuleDescriptorConstPtr prevModule,
                                      ModuleDescriptorConstPtr nextModule) {
    /**
     * This handles the case when an exception that is thrown during translation.
     * We don't want the signals to be attached for code outside of the module.
     */
    m_ins_connection.disconnect();
    m_mod_connection.disconnect();
}

void EdgeDetector::onModuleTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state,
                                               const ModuleDescriptor &module, TranslationBlock *tb, uint64_t pc) {
    /* Disconnect any stale handlers */
    m_ins_connection.disconnect();
    m_mod_connection.disconnect();

    /* Check if we have edges that belong to this module. */
    EdgeCollection::const_iterator it = m_edges.find(module.Name);
    if (it == m_edges.end()) {
        return;
    }

    m_ins_connection = s2e()->getCorePlugin()->onTranslateInstructionEnd.connect(sigc::bind(
        sigc::mem_fun(*this, &EdgeDetector::onTranslateInstructionEnd),
        (-module.LoadBase + module.NativeBase) /* Pass an addend to convert the program counter */, &(*it).second));

    m_mod_connection = m_detector->onModuleTranslateBlockComplete.connect(
        sigc::mem_fun(*this, &EdgeDetector::onModuleTranslateBlockComplete));
}

void EdgeDetector::onTranslateInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                             uint64_t pc, uint64_t addend, const EdgeCollection::Edges *_edges) {
    // If pc is in the source list, add a signal to monitor the destination.
    // There may be multiple destinations (i.e., >=2 edges from the same source).
    uint64_t modulePc = pc + addend;
    const EdgeCollection::Edges &edges = *_edges;

    EdgeCollection::Edges::const_iterator it = edges.find(modulePc);
    if (it == edges.end()) {
        return;
    }

    signal->connect(sigc::bind(sigc::mem_fun(*this, &EdgeDetector::onEdgeInternal), addend, &(*it).second));
}

void EdgeDetector::onEdgeInternal(S2EExecutionState *state, uint64_t sourcePc, uint64_t addend,
                                  const EdgeCollection::EdgeTargets *_targets) {
    // XXX: won't work if there is a call instruction in bb a (as in edge a => b)
    const EdgeCollection::EdgeTargets &targets = *_targets;
    uint64_t moduleDestPc = state->regs()->getPc() + addend;

    foreach2 (it, targets.begin(), targets.end()) {
        const EdgeCollection::EdgeTargetType &target = *it;
        if (moduleDestPc == target.first) {
            if (DebugEdgeDetector) {
                getInfoStream(state) << "EdgeDetector: " << hexval(sourcePc) << " => " << hexval(state->regs()->getPc())
                                     << "\n";
            }
            onEdge.emit(state, sourcePc, target.second);
        }
    }
}

void EdgeDetector::onModuleTranslateBlockComplete(S2EExecutionState *state, const ModuleDescriptor &module,
                                                  TranslationBlock *tb, uint64_t endPc) {
    m_ins_connection.disconnect();
    m_mod_connection.disconnect();
}
} // namespace plugins
} // namespace s2e
