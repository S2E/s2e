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

#ifndef S2E_BIOS_PCI

#define S2E_BIOS_PCI

#include <inttypes.h>

#include <hw/port.h>

#define PCI_VENDOR_ID 0x00 /* 16 bits */
#define PCI_DEVICE_ID 0x02 /* 16 bits */
#define PCI_COMMAND   0x04 /* 16 bits */

#define PCI_REVISION_ID                0x08
#define PCI_BASE_ADDRESS_0             0x10 /* 32 bits */
#define PCI_BASE_ADDRESS_1             0x14 /* 32 bits [htype 0,1 only] */
#define PCI_BASE_ADDRESS_2             0x18 /* 32 bits [htype 0 only] */
#define PCI_BASE_ADDRESS_3             0x1c /* 32 bits */
#define PCI_BASE_ADDRESS_4             0x20 /* 32 bits */
#define PCI_BASE_ADDRESS_5             0x24 /* 32 bits */
#define PCI_BASE_ADDRESS_SPACE         0x01 /* 0 = memory, 1 = I/O */
#define PCI_BASE_ADDRESS_SPACE_IO      0x01
#define PCI_BASE_ADDRESS_SPACE_MEMORY  0x00
#define PCI_BASE_ADDRESS_MEM_TYPE_MASK 0x06
#define PCI_BASE_ADDRESS_MEM_TYPE_32   0x00 /* 32 bit address */
#define PCI_BASE_ADDRESS_MEM_TYPE_1M   0x02 /* Below 1M [obsolete] */
#define PCI_BASE_ADDRESS_MEM_TYPE_64   0x04 /* 64 bit address */
#define PCI_BASE_ADDRESS_MEM_PREFETCH  0x08 /* prefetchable? */
#define PCI_BASE_ADDRESS_MEM_MASK      (~0x0fUL)
#define PCI_BASE_ADDRESS_IO_MASK       (~0x03UL)

#define PCI_CAPABILITY_LIST 0x34 /* Offset of first capability list entry */

static uint8_t pci_read_byte(uint32_t bus, uint32_t device, uint32_t function, unsigned offset) {
    uint32_t address = 0x80000000 | (bus << 16) | (device << 11) | (function << 8) | (offset & 0xfc);
    outl(0xcf8, address);
    return inb(0xcfc + (offset & 3));
}

static uint16_t pci_read_word(uint32_t bus, uint32_t device, uint32_t function, unsigned offset) {
    uint32_t address = 0x80000000 | (bus << 16) | (device << 11) | (function << 8) | (offset & 0xfc);
    outl(0xcf8, address);
    return inw(0xcfc + (offset & 3));
}

static uint32_t pci_read_dword(uint32_t bus, uint32_t device, uint32_t function, unsigned offset) {
    uint32_t address = 0x80000000 | (bus << 16) | (device << 11) | (function << 8) | (offset & 0xfc);
    outl(0xcf8, address);
    return inl(0xcfc);
}

static void pci_write_byte(uint32_t bus, uint32_t device, uint32_t function, unsigned offset, uint8_t value) {
    uint32_t address = 0x80000000 | (bus << 16) | (device << 11) | (function << 8) | (offset & 0xfc);
    outl(0xcf8, address);
    outb(0xcfc + (offset & 0x3), value);
}

static void pci_write_word(uint32_t bus, uint32_t device, uint32_t function, unsigned offset, uint16_t value) {
    uint32_t address = 0x80000000 | (bus << 16) | (device << 11) | (function << 8) | (offset & 0xfc);
    outl(0xcf8, address);
    outw(0xcfc + (offset & 0x3), value);
}

static void pci_write_dword(uint32_t bus, uint32_t device, uint32_t function, unsigned offset, uint32_t value) {
    uint32_t address = 0x80000000 | (bus << 16) | (device << 11) | (function << 8) | (offset & 0xfc);
    outl(0xcf8, address);
    return outl(0xcfc, value);
}

static uint32_t pci_read(uint32_t bus, uint32_t device, uint32_t function, unsigned offset, unsigned size) {
    switch (size) {
        case 1:
            return pci_read_byte(bus, device, function, offset);
            break;
        case 2:
            return pci_read_word(bus, device, function, offset);
            break;
        case 4:
            return pci_read_dword(bus, device, function, offset);
            break;
        default:
            s2e_kill_state(0, "pci_read: incorrect size");
    }
    return 0;
}

typedef struct _barinfo_t {
    uint64_t address;
    uint64_t size;
    int isIo;
    int is64;
} barinfo_t;

uint32_t pci_find_device(uint16_t vid, uint16_t pid, uint8_t *b, uint8_t *d, uint8_t *f);
barinfo_t pci_get_bar_info(uint8_t bus, uint8_t device, uint8_t function, unsigned num);
void pci_set_bar_address(uint8_t bus, uint8_t device, uint8_t function, unsigned num, uint64_t address);
void pci_activate_io(uint8_t bus, uint8_t device, uint8_t function, int io, int mmio);

#endif
