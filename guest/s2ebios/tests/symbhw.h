/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2013 Dependable Systems Laboratory, EPFL
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

#ifndef _S2E_SYMBHW_H_

#define _S2E_SYMBHW_H_

#include <inttypes.h>

/********************************************************/
/* SymbolicHardware */
enum S2E_SYMBHW_COMMANDS {
    SYMBHW_PLUG_IN,
    SYMBHW_HAS_PCI,
    SYMBHW_UNPLUG,
    SYMBHW_REGISTER_DMA_MEMORY,
    SYMBHW_UNREGISTER_DMA_MEMORY,
    SYMBHW_INJECT_INTERRUPT,
    SYMBHW_ACTIVATE_SYMBOLIC_PCI_BUS,
    SYMBHW_QUERY_RESOURCE_SIZE,
    SYMBHW_SELECT_NEXT_PCI_CONFIG,
} __attribute__((packed));

struct S2E_SYMHW_DMA_MEMORY {
    uint64_t PhysicalAddress;
    uint64_t Size;
} __attribute__((packed));

struct S2E_SYMHW_RESOURCE {
    /* Input to identify the resource */
    uint64_t PhysicalAddress;

    /* Output is a constrained symbolic size */
    uint64_t Size;
} __attribute__((packed));

struct S2E_SYMBHW_COMMAND {
    enum S2E_SYMBHW_COMMANDS Command;
    union {
        struct S2E_SYMHW_DMA_MEMORY Memory;
        struct S2E_SYMHW_RESOURCE Resource;
        uint64_t HasPci;
        uint64_t InterruptLevel;
        uint64_t SelectNextConfigSuccess;
    };
} __attribute__((packed));

static void S2ERegisterDmaRegion(uint64_t PhysicalAddress, uint64_t Size) {
    struct S2E_SYMBHW_COMMAND Command;
    Command.Command = SYMBHW_REGISTER_DMA_MEMORY;
    Command.Memory.PhysicalAddress = PhysicalAddress;
    Command.Memory.Size = Size;

    s2e_invoke_plugin("SymbolicHardware", &Command, sizeof(Command));
}

static void S2EFreeDmaRegion(uint64_t PhysicalAddress, uint64_t Size) {
    struct S2E_SYMBHW_COMMAND Command;
    Command.Command = SYMBHW_UNREGISTER_DMA_MEMORY;
    Command.Memory.PhysicalAddress = PhysicalAddress;
    Command.Memory.Size = Size;

    s2e_invoke_plugin("SymbolicHardware", &Command, sizeof(Command));
}

static int SymbHwPciDevPresent(void) {
    struct S2E_SYMBHW_COMMAND Command;
    Command.Command = SYMBHW_HAS_PCI;
    Command.HasPci = 0;
    s2e_invoke_plugin("SymbolicHardware", &Command, sizeof(Command));
    return (int) Command.HasPci;
}

static void InjectSymbolicInterrupt(uint64_t Level) {
    struct S2E_SYMBHW_COMMAND Command;
    Command.Command = SYMBHW_INJECT_INTERRUPT;
    Command.InterruptLevel = Level;
    s2e_invoke_plugin("SymbolicHardware", &Command, sizeof(Command));
}

static void ActivateSymbolicPciBus() {
    struct S2E_SYMBHW_COMMAND Command;
    Command.Command = SYMBHW_ACTIVATE_SYMBOLIC_PCI_BUS;
    s2e_invoke_plugin("SymbolicHardware", &Command, sizeof(Command));
}

static int SymbHwQueryResourceSize(uint64_t PhysicalAddress, uint64_t *Size) {
    struct S2E_SYMBHW_COMMAND Command;
    Command.Command = SYMBHW_QUERY_RESOURCE_SIZE;
    Command.Resource.PhysicalAddress = PhysicalAddress;
    Command.Resource.Size = 0;
    s2e_invoke_plugin("SymbolicHardware", &Command, sizeof(Command));
    *Size = Command.Resource.Size;
    return (*Size) != 0;
}

static void SymbhwHotPlug(int plugin) {
    struct S2E_SYMBHW_COMMAND Command;
    Command.Command = plugin ? SYMBHW_PLUG_IN : SYMBHW_UNPLUG;
    s2e_invoke_plugin("SymbolicHardware", &Command, sizeof(Command));
}

static int SymbhwSelectNextConfig() {
    struct S2E_SYMBHW_COMMAND Command;
    Command.Command = SYMBHW_SELECT_NEXT_PCI_CONFIG;
    Command.SelectNextConfigSuccess = 0;
    s2e_invoke_plugin("SymbolicHardware", &Command, sizeof(Command));
    return Command.SelectNextConfigSuccess;
}

#endif
