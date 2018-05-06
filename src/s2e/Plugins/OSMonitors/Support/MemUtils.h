///
/// Copyright (C) 2018, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_OSMONITOR_MEMUTILS_H
#define S2E_PLUGINS_OSMONITOR_MEMUTILS_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/Vmi.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>

#include <klee/Expr.h>
#include <vector>

namespace s2e {
namespace plugins {

///
/// \brief This plugin exports various memory-related APIs that provide more robust
/// memory accessors.
///
/// A common issue when writing a plugin is to be able to read data from executable files
/// mapped to guest virtual memory. This is may be impossible to do if the guest did not
/// map the memory yet (e.g., demand paging). This plugin provides a fallback mechanism in
/// case of read failure by reverting to executable files stored on the host file system.
///
/// This works as follows:
/// 1. Try to read memory directly, if success, return immediately
/// 2. Determine the module loaded at the given location. Return error in case of failure.
/// 3. Load the binary from disk and attempt a read from there.
///
class MemUtils : public Plugin {
    S2E_PLUGIN

private:
    ModuleMap *m_map;
    Vmi *m_vmi;

public:
    MemUtils(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    klee::ref<klee::Expr> read(S2EExecutionState *state, uint64_t addr);
    klee::ref<klee::Expr> read(S2EExecutionState *state, uint64_t addr, klee::Expr::Width width);
    bool read(S2EExecutionState *state, std::vector<klee::ref<klee::Expr>> &output, uint64_t address, unsigned length);
};
}
}

#endif
