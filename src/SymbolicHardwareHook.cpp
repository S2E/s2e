///
/// Copyright (C) 2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

// clang-format off
#include <s2e/cpu.h>
#include <s2e/SymbolicHardwareHook.h>
#include <s2e/s2e_libcpu.h>
// clang-format on

extern "C" {
unsigned g_s2e_enable_mmio_checks = 0;
}

namespace s2e {

SymbolicPortHook g_symbolicPortHook;
SymbolicMemoryHook g_symbolicMemoryHook;

void SymbolicHardwareHookEnableMmioCallbacks(bool enable) {
    g_s2e_enable_mmio_checks = enable;
}
}

int s2e_is_port_symbolic(uint64_t port) {
    return s2e::g_symbolicPortHook.symbolic(port);
}

int s2e_is_mmio_symbolic(uint64_t phys_addr, unsigned size) {
    return s2e::g_symbolicMemoryHook.symbolic(NULL, phys_addr, size);
}

int se_is_mmio_symbolic(struct MemoryDesc *mr, uint64_t address, uint64_t size) {
    return s2e::g_symbolicMemoryHook.symbolic(mr, address, size);
}

int se_is_mmio_symbolic_b(struct MemoryDesc *mr, uint64_t address) {
    return s2e::g_symbolicMemoryHook.symbolic(mr, address, 1);
}

int se_is_mmio_symbolic_w(struct MemoryDesc *mr, uint64_t address) {
    return s2e::g_symbolicMemoryHook.symbolic(mr, address, 2);
}

int se_is_mmio_symbolic_l(struct MemoryDesc *mr, uint64_t address) {
    return s2e::g_symbolicMemoryHook.symbolic(mr, address, 4);
}

int se_is_mmio_symbolic_q(struct MemoryDesc *mr, uint64_t address) {
    return s2e::g_symbolicMemoryHook.symbolic(mr, address, 8);
}
