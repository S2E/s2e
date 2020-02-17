///
/// Copyright (C) 2013, Dependable Systems Laboratory, EPFL
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
} // namespace s2e

int s2e_is_port_symbolic(uint64_t port) {
    return s2e::g_symbolicPortHook.symbolic(port);
}

int s2e_is_mmio_symbolic(uint64_t phys_addr, unsigned size) {
    return s2e::g_symbolicMemoryHook.symbolic(nullptr, phys_addr, size);
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
