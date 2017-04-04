///
/// Copyright (C) 2013, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
     * be read with state->getPc().
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

    void onModuleTransition(S2EExecutionState *state, const ModuleDescriptor *prevModule,
                            const ModuleDescriptor *nextModule);

    void onEdgeInternal(S2EExecutionState *state, uint64_t sourcePc, uint64_t addend,
                        const EdgeCollection::EdgeTargets *target);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_EXAMPLE_H
