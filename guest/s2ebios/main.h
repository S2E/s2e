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

#ifndef S2E_BIOS_MAIN

#define S2E_BIOS_MAIN

void test_symbhw_io_ports();
void test_symbhw_mmio();
void test_symbhw_pci_bars();
void test_symbhw_pci_immutable_fields();
void test_symbhw_pci_extraspace();
void test_symbhw_symbolic_port_writes();
void test_symbhw_query_resource_size();
void test_symbhw_unaligned_reads();
void test_symbhw_unaligned_cmd_port();
void test_symbhw_hotplug();
void test_symbhw_multiple_mappings();
void test_symbhw_multiple_mappings_io();
void test_symbhw_select_config_single_path();
void test_symbhw_select_config_multi_path();
void test_symbhw_switch_config_symbbus();

void test_range1();

void test_selfmod1();

void test_constraints1();

void test_maze();

#endif
