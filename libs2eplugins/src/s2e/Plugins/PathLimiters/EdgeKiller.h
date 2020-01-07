///
/// Copyright (C) 2011-2013, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_EdgeKiller_H
#define S2E_PLUGINS_EdgeKiller_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/Plugins/StaticAnalysis/EdgeDetector.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {
namespace plugins {

class EdgeKiller : public Plugin, public IEdgeAdder {
    S2E_PLUGIN
public:
    EdgeKiller(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();
    void addEdge(const std::string &moduleName, uint64_t start, uint64_t end, EdgeType type);

private:
    ModuleExecutionDetector *m_detector;
    EdgeDetector *m_edgeDetector;
    EdgeCollection m_edges;

    void onEdge(S2EExecutionState *state, uint64_t source, EdgeType type);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_EdgeKiller_H
