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

/**************************************************************************
 * IO ports API
 */

#ifndef IOPORT_H
#define IOPORT_H

#include <cpu/types.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CPUX86State CPUX86State;
typedef uint32_t pio_addr_t;

#define MAX_IOPORTS  (64 * 1024)
#define IOPORTS_MASK (MAX_IOPORTS - 1)

void cpu_outb(pio_addr_t addr, uint8_t val);
void cpu_outw(pio_addr_t addr, uint16_t val);
void cpu_outl(pio_addr_t addr, uint32_t val);
uint8_t cpu_inb(pio_addr_t addr);
uint16_t cpu_inw(pio_addr_t addr);
uint32_t cpu_inl(pio_addr_t addr);

uint64_t cpu_mmio_read(target_phys_addr_t addr, unsigned size);
void cpu_mmio_write(target_phys_addr_t addr, uint64_t data, unsigned size);

uint64_t cpu_apic_get_tpr(CPUX86State *env);
void cpu_apic_set_tpr(CPUX86State *env, uint64_t new_tpr);
uint64_t cpu_apic_get_base(CPUX86State *env);
void cpu_apic_set_base(CPUX86State *env, uint64_t new_base);

typedef uint64_t (*cpu_ioport_read_t)(pio_addr_t addr, unsigned size);
typedef void (*cpu_ioport_write_t)(pio_addr_t addr, uint64_t data, unsigned size);

typedef uint64_t (*cpu_mmio_read_t)(target_phys_addr_t addr, unsigned size);
typedef void (*cpu_mmio_write_t)(target_phys_addr_t addr, uint64_t data, unsigned size);

typedef uint64_t (*cpu_lapic_get_base_t)(CPUX86State *env);
typedef void (*cpu_lapic_set_base_t)(CPUX86State *env, uint64_t new_base);

typedef uint64_t (*cpu_lapic_get_tpr_t)(CPUX86State *env);
typedef void (*cpu_lapic_set_tpr_t)(CPUX86State *env, uint64_t new_tpr);

struct cpu_io_funcs_t {
    cpu_ioport_read_t io_read;
    cpu_ioport_write_t io_write;
    cpu_mmio_read_t mmio_read;
    cpu_mmio_write_t mmio_write;
    cpu_lapic_get_base_t lapic_get_base;
    cpu_lapic_set_base_t lapic_set_base;
    cpu_lapic_get_tpr_t lapic_get_tpr;
    cpu_lapic_set_tpr_t lapic_set_tpr;
};

void cpu_register_io(const struct cpu_io_funcs_t *f);

#ifdef __cplusplus
}
#endif

#endif
