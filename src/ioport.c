/// Copyright (C) 2016  Cyberhaven
/// Copyrights of all contributions belong to their respective owners.
///
/// This library is free software; you can redistribute it and/or
/// modify it under the terms of the GNU Library General Public
/// License as published by the Free Software Foundation; either
/// version 2 of the License, or (at your option) any later version.
///
/// This library is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
/// Library General Public License for more details.
///
/// You should have received a copy of the GNU Library General Public
/// License along with this library; if not, see <http://www.gnu.org/licenses/>.

#include <cpu/ioport.h>

static struct cpu_io_funcs_t s_io;

void cpu_register_io(const struct cpu_io_funcs_t *f) {
    s_io = *f;
}

/***********************************************************/

void cpu_outb(pio_addr_t addr, uint8_t val) {
    s_io.io_write(addr, val, 1);
}

void cpu_outw(pio_addr_t addr, uint16_t val) {
    s_io.io_write(addr, val, 2);
}

void cpu_outl(pio_addr_t addr, uint32_t val) {
    s_io.io_write(addr, val, 4);
}

uint8_t cpu_inb(pio_addr_t addr) {
    return s_io.io_read(addr, 1);
}

uint16_t cpu_inw(pio_addr_t addr) {
    return s_io.io_read(addr, 2);
}

uint32_t cpu_inl(pio_addr_t addr) {
    return s_io.io_read(addr, 4);
}

uint64_t cpu_mmio_read(target_phys_addr_t addr, unsigned size) {
    return s_io.mmio_read(addr, size);
}

void cpu_mmio_write(target_phys_addr_t addr, uint64_t data, unsigned size) {
    s_io.mmio_write(addr, data, size);
}
