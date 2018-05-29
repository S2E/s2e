///
/// Copyright (C) 2014-2018, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/Plugins/OSMonitors/Support/MemoryMap.h>

#include "BaseLinuxMonitor.h"

namespace s2e {
namespace plugins {

/// Verify that the custom  at the given ptr address is valid
bool BaseLinuxMonitor::verifyLinuxCommand(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize,
                                          uint8_t *cmd) {
    // Validate the size of the instruction
    s2e_assert(state, guestDataSize == m_commandSize, "Invalid command size "
                                                          << guestDataSize << " != " << m_commandSize
                                                          << " from pagedir=" << hexval(state->regs()->getPageDir())
                                                          << " pc=" << hexval(state->regs()->getPc()));

    // Read any symbolic bytes
    std::ostringstream symbolicBytes;
    for (unsigned i = 0; i < guestDataSize; ++i) {
        ref<Expr> t = state->mem()->read(guestDataPtr + i);
        if (!t.isNull() && !isa<ConstantExpr>(t)) {
            symbolicBytes << "  " << hexval(i, 2) << "\n";
        }
    }

    if (symbolicBytes.str().length()) {
        getWarningsStream(state) << "Command has symbolic bytes at " << symbolicBytes.str() << "\n";
    }

    // Read the instruction
    bool ok = state->mem()->read(guestDataPtr, cmd, guestDataSize);
    s2e_assert(state, ok, "Failed to read instruction memory");

    // Validate the instruction's version

    // The version field comes always first in all commands
    uint64_t version = *(uint64_t *) cmd;

    if (version != m_commandVersion) {
        std::ostringstream os;

        for (unsigned i = 0; i < guestDataSize; ++i) {
            os << hexval(cmd[i]) << " ";
        }

        getWarningsStream(state) << "Command bytes: " << os.str() << "\n";

        s2e_assert(state, false, "Invalid command version " << hexval(version) << " != " << hexval(m_commandVersion)
                                                            << " from pagedir=" << hexval(state->regs()->getPageDir())
                                                            << " pc=" << hexval(state->regs()->getPc()));
    }

    return true;
}

bool BaseLinuxMonitor::getCurrentStack(S2EExecutionState *state, uint64_t *base, uint64_t *size) {
    auto pid = getPid(state);

    uint64_t start, end;
    MemoryMapRegionType type;

    if (!m_map->lookupRegion(state, pid, state->regs()->getSp(), start, end, type)) {
        return false;
    }

    *base = start;
    *size = end - start;

    return true;
}
}
}
