///
/// Copyright (C) 2018, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include "MemUtils.h"

namespace s2e {
namespace plugins {

using namespace klee;

S2E_DEFINE_PLUGIN(MemUtils, "Various memory-related utilities that require OS support", "", "ModuleMap", "Vmi");

void MemUtils::initialize() {
    m_vmi = s2e()->getPlugin<Vmi>();
    m_map = s2e()->getPlugin<ModuleMap>();
}

ref<Expr> MemUtils::read(S2EExecutionState *state, uint64_t addr, klee::Expr::Width width) {
    ref<Expr> expr = state->mem()->read(addr, width);
    if (!expr.isNull()) {
        return expr;
    }

    // Try to read data from executable image
    const ModuleDescriptor *module = m_map->getModule(state, state->regs()->getPc());
    if (!module) {
        getDebugStream(state) << "no current module\n";
        return ref<Expr>(NULL);
    }

    uintmax_t value = 0;
    for (unsigned i = 0; i < Expr::getMinBytesForWidth(width); i++) {
        uint8_t byte;
        if (!m_vmi->readModuleData(*module, addr + i, byte)) {
            getDebugStream(state) << "Failed to read memory at address " << hexval(addr) << "\n";
            return ref<Expr>(NULL);
        }
        value |= ((uintmax_t) byte) << (i * CHAR_BIT);
    }

    return ConstantExpr::create(value, width);
}

klee::ref<klee::Expr> MemUtils::read(S2EExecutionState *state, uint64_t addr) {
    return read(state, addr, Expr::Int8);
}

bool MemUtils::read(S2EExecutionState *state, std::vector<ref<Expr>> &output, uint64_t address, unsigned length) {
    for (unsigned i = 0; i < length; ++i) {
        ref<Expr> e = read(state, address + i);
        if (e.isNull()) {
            getWarningsStream(state) << "Could not read byte at " << hexval(address + i) << "\n";
            return false;
        }
        output.push_back(e);
    }
    return true;
}
}
}
