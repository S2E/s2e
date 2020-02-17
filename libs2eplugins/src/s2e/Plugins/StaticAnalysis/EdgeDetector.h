///
/// Copyright (C) 2013, Dependable Systems Laboratory, EPFL
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

#ifndef S2E_PLUGINS_EDGEDETECTOR_H
#define S2E_PLUGINS_EDGEDETECTOR_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {
namespace plugins {

enum EdgeType { EDGE_NONE, EDGE_LOOP_ENTRY, EDGE_LOOP_BACKEDGE, EDGE_LOOP_EXIT };

class IEdgeAdder {
public:
    virtual ~IEdgeAdder() {
    }
    virtual void addEdge(const std::string &moduleName, uint64_t start, uint64_t end, EdgeType type) = 0;
};

class EdgeCollection {
public:
    typedef std::pair<uint64_t, EdgeType> EdgeTargetType;

    typedef llvm::SmallVector<EdgeTargetType, 2> EdgeTargets;

    /* Maps a source program counter to a set of destinations */
    typedef llvm::DenseMap<uint64_t, EdgeTargets> Edges;

    /* Maps a module name to its set of edges */
    typedef std::map<std::string, Edges> ModuleEdges;

    typedef ModuleEdges::const_iterator const_iterator;

private:
    ModuleEdges m_edges;

public:
    bool findEdge(const std::string &moduleName, uint64_t start, uint64_t end, EdgeType *result);
    void addEdge(const std::string &moduleName, uint64_t start, uint64_t end, EdgeType type);

    const_iterator end() const {
        return m_edges.end();
    }
    const_iterator find(const ModuleEdges::key_type &key) const {
        return m_edges.find(key);
    }
};

class EdgeDetector : public Plugin, public IEdgeAdder {
    S2E_PLUGIN
public:
    EdgeDetector(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    /**
     * Other plugins can use this only during their configuration phase.
     */
    void addEdge(const std::string &moduleName, uint64_t start, uint64_t end, EdgeType type);

    /**
     * Signal that is emitted when an edge is detected.
     * Only transmit the source instruction. The destination can
     * be read with state->regs()->getPc().
     */
    sigc::signal<void, S2EExecutionState *, uint64_t /* source pc */, EdgeType> onEdge;

    bool findEdge(const std::string &moduleName, uint64_t start, uint64_t end, EdgeType *result);

    void readConfig(const std::string &configKey, IEdgeAdder *adder);

private:
    sigc::connection m_ins_connection;
    sigc::connection m_mod_connection;

    EdgeCollection m_edges;
    ModuleExecutionDetector *m_detector;

    void onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module);

    void onModuleTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, const ModuleDescriptor &module,
                                     TranslationBlock *tb, uint64_t pc);

    void onTranslateInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc,
                                   uint64_t addend, const EdgeCollection::Edges *edges);

    void onModuleTranslateBlockComplete(S2EExecutionState *state, const ModuleDescriptor &module, TranslationBlock *tb,
                                        uint64_t endPc);

    void onModuleTransition(S2EExecutionState *state, ModuleDescriptorConstPtr prevModule,
                            ModuleDescriptorConstPtr nextModule);

    void onEdgeInternal(S2EExecutionState *state, uint64_t sourcePc, uint64_t addend,
                        const EdgeCollection::EdgeTargets *target);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_EXAMPLE_H
