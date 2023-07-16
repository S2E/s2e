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

#include <hw/hw.h>
#include <inttypes.h>
#include <stdio.h>
#include <utils/interrupt.h>
#include <vmm/vmm.h>

#include <s2e/s2e.h>

#include "main.h"

void main(void) {
    /* Init basic plugin environment */
    // s2e_raw_register_stack(&s_stack);

    // test_range1();
    // test_constraints1();
    // test_symbhw_mmio();
    // test_symbhw_io_ports();
    // test_symbhw_pci_bars();
    // test_symbhw_pci_immutable_fields();
    // test_symbhw_pci_extraspace();
    // test_symbhw_symbolic_port_writes();
    // test_symbhw_query_resource_size();
    // test_symbhw_unaligned_reads();
    // test_symbhw_unaligned_cmd_port();
    // test_symbhw_hotplug();
    // test_symbhw_multiple_mappings();
    // test_symbhw_multiple_mappings_io();
    // test_symbhw_select_config_single_path();
    // test_symbhw_select_config_multi_path();
    // test_symbhw_switch_config_symbbus();

    // test_selfmod1();

    // test_iospeed();
    // test_fork();
    // test_maze();

    printf("Initing memory manager\n");
    vmm_init();

    printf("Initing interrupt table\n");
    interrupts_init();

    printf("Initing IOAPIC\n");
    ioapic_init();

    apic_init();

#if __WORD_SIZE == 64
    printf("test_memory_rw_new_page\n");
    test_memory_rw_new_page();

    printf("test_memory_rw_same_page_unaligned\n");
    test_memory_rw_same_page_unaligned();

    printf("test_memory_rw_same_page_unaligned_signed\n");
    test_memory_rw_same_page_unaligned_signed();
#endif

    while (1) {
        __asm__("hlt");
    }

    s2e_kill_state(0, "done");
}
