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

#include <s2e/monitors/raw.h>
#include <s2e/s2e.h>

#include <inttypes.h>

#include "helper.h"
#include "main.h"

#if defined(S2E_PLUGIN_DIR)
void test_external(void);
#endif

static struct S2E_RAWMON_COMMAND_STACK s_stack = {.stack_size = 0x1000, .stack_base = 0x80000 - 0x1000};

static void test_iospeed(void) {
    const uint32_t max_iter = 100 * 1000 * 1000;
    for (uint32_t i = 0; i < max_iter; ++i) {
        inl(0xcfc);
    }
}

void main(void) {
    /* Init basic plugin environment */
    s2e_raw_register_stack(&s_stack);

// test_range1();
// test_constraints1();
#if defined(S2E_PLUGIN_DIR)
    test_external();
#endif
    test_symbhw_mmio();
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

    s2e_kill_state(0, "done");
}
