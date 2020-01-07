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

#include <s2e/s2e.h>

#include "pci.h"
#include "symbhw.h"

#define TEST_VID 0x10ec
#define TEST_PID 0x8139

void test_symbhw_io_ports(void) {
    uint32_t val;
    val = inl(0x100);
    if (val == 0x12345678) {
        s2e_kill_state(val, "done");
    }

    val = inw(0x102);
    if (val == 0x1234) {
        s2e_kill_state(val, "done");
    }

    val = inb(0x103);
    if (val == 0x12) {
        s2e_kill_state(val, "done");
    }
}

union uptr_t {
    volatile uintptr_t ptr;
    volatile uint8_t *b;
    volatile uint16_t *w;
    volatile uint32_t *d;
};

union udata_t {
    uint32_t v;
    uint8_t a[4];
    uint16_t aw[2];
};

static void test_symbhw_mmio_range(uintptr_t start, uintptr_t end) {
    union uptr_t p;
    union udata_t d;

    p.ptr = start;
    d.v = *p.b;
    s2e_assert(s2e_is_symbolic(&d.a[0], sizeof(d.a[0])));
    s2e_assert(d.a[1] == 0);
    s2e_assert(d.a[2] == 0);
    s2e_assert(d.a[3] == 0);

    d.v = *p.w;
    s2e_assert(s2e_is_symbolic(&d.aw[0], sizeof(d.aw[0])));
    s2e_assert(d.aw[1] == 0);

    d.v = *p.d;
    s2e_assert(s2e_is_symbolic(&d.v, sizeof(d.v)));
}

static void test_symbhw_dma_range(uintptr_t start, uintptr_t end) {
    s2e_message("==== Testing access within dma range ====");
    test_symbhw_mmio_range(start, end);

    s2e_message("==== Testing overlapping dma range ====");
    union uptr_t p;
    union udata_t d;

    p.ptr = end + 1;
    *p.d = 0xdeadbeef;
    s2e_assert(!s2e_is_symbolic((uint32_t *) p.d, sizeof(*p.d)));
    s2e_assert(*p.d == 0xdeadbeef);

    p.ptr = end - 1;
    *p.d = 0xdeadbeef;
    d.v = *p.d;
    s2e_assert(d.aw[1] == 0xdead);
    s2e_assert(s2e_is_symbolic(&d.aw[0], sizeof(d.aw[0])));
}

///
/// \brief test_symbhw_mmio tests symbolic hardware basics
///
/// Note: configure SymbolicHardware plugin with the required
/// memory ranges.
///
/// TODO: configure symbolic hardware programmatically
///
void test_symbhw_mmio() {
    const uint32_t p1 = 0xfc000000;
    const uint32_t p2 = 0xfc00ffff;

    s2e_message("==== Aligned case ====");
    test_symbhw_mmio_range(p1, p2);

    s2e_message("==== Unaligned case ==== ");
    test_symbhw_mmio_range(p1 + 1, p2);

    const uint32_t m1 = 0x150000;
    const uint32_t m2 = 0x1500ff;
    test_symbhw_dma_range(m1, m2);
}

/* XXX: global vars are read only (in ROM!) */
#define TEST_START_PHYS_ADDR 0xe0000000
#define TEST_START_PORT 0x1000

static void test_map_registers(uint8_t bus, uint8_t device, uint8_t function, uint32_t *phys_start,
                               uint16_t *phys_port_start) {
    for (unsigned i = 0; i < 5; ++i) {
        barinfo_t info = pci_get_bar_info(bus, device, function, i);
        if (info.size == 0) {
            continue;
        }

        uint32_t addr = info.isIo ? *phys_port_start : *phys_start;
        pci_set_bar_address(bus, device, function, i, addr);
        if (info.is64) {
            ++i;
        }

        if (info.isIo) {
            *phys_port_start += 0x100;
        } else {
            *phys_start += 0x100000; // 1MB alignment
        }
    }
}

static void test_symbhw_setup(uint8_t *bus, uint8_t *device, uint8_t *function) {
    s2e_message("====== Looking for symbolic pci device...");
    uint32_t ret = pci_find_device(TEST_VID, TEST_PID, bus, device, function);
    if (!ret) {
        s2e_kill_state(ret, "Could not find symbolic PCI device");
    }

    s2e_message("====== Mapping device registers...");
    uint32_t addr = TEST_START_PHYS_ADDR;
    uint16_t port = TEST_START_PORT;

    test_map_registers(*bus, *device, *function, &addr, &port);
    pci_activate_io(*bus, *device, *function, 1, 1);

    s2e_message("====== Enabling symbolic config space...");
    ActivateSymbolicPciBus();
}

void test_symbhw_pci_extraspace() {
    uint8_t bus, device, function;
    test_symbhw_setup(&bus, &device, &function);

    s2e_message("====== Checking extended config space...");
    uint8_t byte = pci_read_byte(bus, device, function, 0x40);
    s2e_print_expression("test_symbhw_pci_extraspace: byte 0x40", byte);

    if (byte == 23) {
        s2e_kill_state(0, "test_symbhw_pci_extraspace: got 23");
    }
}

static void test_symbhw_pci_check_immutable_field(uint8_t bus, uint8_t device, uint8_t function, unsigned offset,
                                                  unsigned size) {
    uint32_t value = pci_read(bus, device, function, offset, size);

    s2e_print_expression("test_symbhw_pci_check_field: read", value);

    if (value == 23) {
        /* Check that one can't overwrite it */
        pci_write_byte(bus, device, function, offset, 123);

        value = pci_read(bus, device, function, offset, size);

        s2e_assert(value == 23);
    }
}

void test_symbhw_pci_immutable_fields() {
    uint8_t bus, device, function;
    test_symbhw_setup(&bus, &device, &function);

    s2e_message("====== Checking revision id...");
    test_symbhw_pci_check_immutable_field(bus, device, function, PCI_REVISION_ID, 1);

    s2e_message("====== Checking capabilities...");
    test_symbhw_pci_check_immutable_field(bus, device, function, PCI_CAPABILITY_LIST, 1);
}

/**
 * Tests that the symbolic hardware is properly configured
 */
void test_symbhw_pci_bars() {
    uint8_t bus, device, function;
    test_symbhw_setup(&bus, &device, &function);

    s2e_message("====== Testing symbolic bar...");
    barinfo_t info = pci_get_bar_info(bus, device, function, 0);

    if (info.size != 0x20) {
        s2e_kill_state(0, "Size must be 0x20");
    }

    info = pci_get_bar_info(bus, device, function, 1);
    if (info.size != 0x1000) {
        s2e_kill_state(0, "Size must be 0x1000");
    }
}

/* Check that symbolic values are properly concretized */
/* There shouldn't be KLEE errors in the log (failed external) */
void test_symbhw_symbolic_port_writes() {
    uint8_t bus, device, function;
    test_symbhw_setup(&bus, &device, &function);

    s2e_message("====== Testing symbolic port writes...");
    uint32_t val;
    s2e_make_symbolic(&val, sizeof(val), "symbolic_value");
    pci_write_dword(bus, device, function, 0x40, val);
    pci_write_byte(bus, device, function, PCI_CAPABILITY_LIST, val);
}

void test_symbhw_query_resource_size() {
    uint8_t bus, device, function;
    test_symbhw_setup(&bus, &device, &function);

    s2e_message("====== Testing symbolic resource size query...");
    barinfo_t info = pci_get_bar_info(bus, device, function, 0);
    s2e_assert(info.isIo);
    s2e_assert(info.address <= 0x1000);

    uint64_t size;
    SymbHwQueryResourceSize(info.address, &size);
    s2e_assert(size > 0 && size <= 0x100);

    // 64-bits
    info = pci_get_bar_info(bus, device, function, 2);
    s2e_assert(!info.isIo);
    s2e_assert(info.is64);
    s2e_assert(info.size > 0 && info.size <= 0x10000);
}

/* Test that unaligned reads from the PCI region */
/* case1: read entirely with a bar of 1, 2, 4 bytes */
/* case2: read overlaps */
void test_symbhw_unaligned_reads() {
    uint8_t bus, device, function;
    test_symbhw_setup(&bus, &device, &function);

    s2e_message("====== Testing reading 2 bytes from bar0...");
    uint16_t vid = pci_read(bus, device, function, PCI_VENDOR_ID, 2);
    s2e_assert(vid == TEST_VID);

    uint16_t pid = pci_read(bus, device, function, PCI_DEVICE_ID, 2);
    s2e_assert(pid == TEST_PID);

    uint16_t pvid = pci_read(bus, device, function, PCI_VENDOR_ID + 1, 2);
    s2e_print_expression("test_symbhw_unaligned_reads pvid", pvid);
    s2e_assert(pvid == 0x3910);

    uint16_t val = pci_read(bus, device, function, PCI_BASE_ADDRESS_0, 2);
    s2e_assert(val == (TEST_START_PORT | 1));

    val = pci_read(bus, device, function, PCI_BASE_ADDRESS_0 + 2, 2);
    s2e_assert(val == 0);
}

/**
 * Fragment the command into multiple chunks
 */
void test_symbhw_unaligned_cmd_port() {
    uint8_t bus, device, function;
    test_symbhw_setup(&bus, &device, &function);

    s2e_message("====== Testing fragmented command...");

    uint32_t offset = PCI_VENDOR_ID;
    uint32_t address = 0x80000000 | (bus << 16) | (device << 11) | (function << 8) | (offset & 0xfc);
    outw(0xcf8, address & 0xFFFF);
    outw(0xcf8 + 2, address >> 16);
    uint16_t vid = inw(0xcfc);
    s2e_print_expression("test_symbhw_unaligned_cmd_port: vid", vid);
    s2e_assert(vid == TEST_VID);
}

void test_symbhw_hotplug() {
    SymbhwHotPlug(0);

    /* Check that the device can be plugged/unplugged */
    uint8_t bus, device, function;
    uint32_t ret = pci_find_device(TEST_VID, TEST_PID, &bus, &device, &function);
    s2e_assert(!ret);

    SymbhwHotPlug(1);
    ret = pci_find_device(TEST_VID, TEST_PID, &bus, &device, &function);
    s2e_assert(ret);

    /* Check that the device can be plugged/unplugged in different states */
    /* Note: assumes DFS search strategy */
    int val = 1;
    s2e_make_symbolic(&val, sizeof(val), "val");

    if (val) {
        SymbhwHotPlug(0);
        ret = pci_find_device(TEST_VID, TEST_PID, &bus, &device, &function);
        s2e_assert(!ret);
        s2e_kill_state(0, "done");
    }

    ret = pci_find_device(TEST_VID, TEST_PID, &bus, &device, &function);
    s2e_assert(ret);
}

void test_symbhw_multiple_mappings() {
    uint8_t bus, device, function;
    uint32_t ret = pci_find_device(TEST_VID, TEST_PID, &bus, &device, &function);
    s2e_assert(ret);

    int val = 1;
    s2e_make_symbolic(&val, sizeof(val), "val");

    if (val) {
        /* Try to map the device in one memory location */
        uint32_t addr = TEST_START_PHYS_ADDR;
        uint16_t port = TEST_START_PORT;

        test_map_registers(bus, device, function, &addr, &port);
        pci_activate_io(bus, device, function, 1, 1);

        uint32_t base = pci_read_dword(bus, device, function, PCI_BASE_ADDRESS_0);
        s2e_assert(base == (TEST_START_PORT | 1));
        s2e_kill_state(0, "done");
    }

    uint32_t base = pci_read_dword(bus, device, function, PCI_BASE_ADDRESS_0);
    s2e_assert(base == 1);
}

/* Try to do I/O in multiple mappings */
void test_symbhw_multiple_mappings_io() {
    uint8_t bus, device, function;
    uint32_t ret = pci_find_device(TEST_VID, TEST_PID, &bus, &device, &function);
    s2e_assert(ret);

    int val = 1;
    s2e_make_symbolic(&val, sizeof(val), "val");

    if (val) {
        uint32_t addr = 0xe0000000;
        uint16_t port = 0x1000;

        test_map_registers(bus, device, function, &addr, &port);
        pci_activate_io(bus, device, function, 1, 1);

        uint32_t s = inl(0x1000);
        s2e_assert(s2e_is_symbolic(&s, sizeof(s)));

        s = inl(0x2000);
        s2e_assert(!s2e_is_symbolic(&s, sizeof(s)));

        uint32_t ms = *(uint32_t *) 0xe0000000;
        s2e_assert(s2e_is_symbolic(&ms, sizeof(ms)));

        ms = *(uint32_t *) 0xf0000000;
        s2e_assert(!s2e_is_symbolic(&ms, sizeof(ms)));
    } else {
        uint32_t addr = 0xf0000000;
        uint16_t port = 0x2000;

        test_map_registers(bus, device, function, &addr, &port);
        pci_activate_io(bus, device, function, 1, 1);

        uint32_t s = inl(0x1000);
        s2e_assert(!s2e_is_symbolic(&s, sizeof(s)));

        s = inl(0x2000);
        s2e_assert(s2e_is_symbolic(&s, sizeof(s)));

        uint32_t ms = *(uint32_t *) 0xf0000000;
        s2e_assert(s2e_is_symbolic(&ms, sizeof(ms)));

        ms = *(uint32_t *) 0xe0000000;
        s2e_assert(!s2e_is_symbolic(&ms, sizeof(ms)));
    }
}

void test_symbhw_select_config_single_path() {
    uint8_t bus, device, function;
    uint32_t ret = pci_find_device(TEST_VID, TEST_PID, &bus, &device, &function);
    s2e_assert(ret);

    uint32_t addr = 0xe0000000;
    uint16_t port = 0x1000;

    test_map_registers(bus, device, function, &addr, &port);
    pci_activate_io(bus, device, function, 1, 1);

    uint32_t bar0, bar1;
    barinfo_t bar0_info;
    int is_io;

    /* ===== First config is the default one ===== */
    s2e_message("test_symbhw_select_config_single_path: config 0");
    bar0 = pci_read_dword(bus, device, function, PCI_BASE_ADDRESS_0);
    s2e_assert(bar0 == (0x1000 | 1));
    bar1 = pci_read_dword(bus, device, function, PCI_BASE_ADDRESS_1);
    s2e_assert(bar1 == 0xe0000000);

    /* ===== Second config ===== */
    s2e_message("test_symbhw_select_config_single_path: config 1");
    ret = SymbhwSelectNextConfig();
    s2e_assert(ret);

    /* Check that the device is initially disabled */
    bar0 = pci_read_dword(bus, device, function, PCI_BASE_ADDRESS_0);
    s2e_assert(bar0 == ~0);

    SymbhwHotPlug(1);
    bar0_info = pci_get_bar_info(bus, device, function, 0);
    s2e_assert(bar0_info.size == 0x100 && bar0_info.isIo);
    bar1 = pci_read_dword(bus, device, function, PCI_BASE_ADDRESS_1);
    s2e_assert(bar1 == 0);

    /* ===== Third config ===== */
    s2e_message("test_symbhw_select_config_single_path: config 2");
    ret = SymbhwSelectNextConfig();
    s2e_assert(ret);
    SymbhwHotPlug(1);
    bar0_info = pci_get_bar_info(bus, device, function, 0);
    s2e_assert(bar0_info.size == 0x10000 && !bar0_info.isIo);
    bar1 = pci_read_dword(bus, device, function, PCI_BASE_ADDRESS_1);
    s2e_assert(bar1 == 0);
}

void test_symbhw_select_config_multi_path() {
    uint8_t bus, device, function;
    uint32_t ret = pci_find_device(TEST_VID, TEST_PID, &bus, &device, &function);
    s2e_assert(ret);

    uint32_t addr = 0xe0000000;
    uint16_t port = 0x1000;

    test_map_registers(bus, device, function, &addr, &port);
    pci_activate_io(bus, device, function, 1, 1);

    uint32_t bar0, bar1;
    barinfo_t bar0_info;
    int is_io;

    int val = 0; // Back track to first config in DFS mode
    s2e_make_symbolic(&val, sizeof(val), "val");

    if (val) {
        // Config 0 here
        bar0 = pci_read_dword(bus, device, function, PCI_BASE_ADDRESS_0);
        s2e_assert(bar0 == (0x1000 | 1));
        bar1 = pci_read_dword(bus, device, function, PCI_BASE_ADDRESS_1);
        s2e_print_expression("test_symbhw_select_config_multi_path bar1 true", bar1);
        s2e_assert(bar1 == 0xe0000000);

        uint32_t s = inl(0x1000);
        s2e_assert(s2e_is_symbolic(&s, sizeof(s)));

        uint32_t ms = *(uint32_t *) 0xe0000000;
        s2e_assert(s2e_is_symbolic(&ms, sizeof(ms)));
    } else {
        // Config 2 here
        ret = SymbhwSelectNextConfig();
        s2e_assert(ret && "Could not go to next config");
        ret = SymbhwSelectNextConfig();
        s2e_assert(ret && "Could not go to next config");

        SymbhwHotPlug(1);
        bar0_info = pci_get_bar_info(bus, device, function, 0);
        s2e_assert(bar0_info.size == 0x10000 && !bar0_info.isIo);
        bar1 = pci_read_dword(bus, device, function, PCI_BASE_ADDRESS_1);
        s2e_assert(bar1 == 0);
    }
}

/* Switch the PCI config while the symbolic bus is enabled */
void test_symbhw_switch_config_symbbus() {
    uint8_t bus, device, function;
    uint32_t ret = pci_find_device(TEST_VID, TEST_PID, &bus, &device, &function);
    s2e_assert(ret);

    uint32_t addr = 0xe0000000;
    uint16_t port = 0x1000;

    test_map_registers(bus, device, function, &addr, &port);
    pci_activate_io(bus, device, function, 1, 1);

    int val = 1;
    s2e_make_symbolic(&val, sizeof(val), "val");

    if (val) {
        ActivateSymbolicPciBus();
        SymbhwHotPlug(0);
    } else {
        uint32_t bar0 = pci_read_dword(bus, device, function, PCI_BASE_ADDRESS_0);
        s2e_assert(bar0 == 0x1001);
    }
}
