/// Copyright (C) 2003  Fabrice Bellard
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

#ifndef CPU_COMMON_H
#define CPU_COMMON_H 1

/* CPU interfaces that are target independent.  */

#include <cpu/types.h>

#ifdef __cplusplus
extern "C" {
#endif

void cpu_physical_memory_rw(target_phys_addr_t addr, uint8_t *buf, int len, int is_write);

void cpu_host_memory_rw(uintptr_t source, uintptr_t dest, int length, int is_write);

static inline void cpu_physical_memory_read(target_phys_addr_t addr, void *buf, int len) {
    cpu_physical_memory_rw(addr, (uint8_t *) buf, len, 0);
}

static inline void cpu_physical_memory_write(target_phys_addr_t addr, const void *buf, int len) {
    cpu_physical_memory_rw(addr, (uint8_t *) buf, len, 1);
}

uint32_t ldub_phys(target_phys_addr_t addr);
uint32_t lduw_phys(target_phys_addr_t addr);
uint32_t ldl_phys(target_phys_addr_t addr);
uint64_t ldq_phys(target_phys_addr_t addr);

void stb_phys(target_phys_addr_t addr, uint32_t val);
void stw_phys(target_phys_addr_t addr, uint32_t val);
void stl_phys(target_phys_addr_t addr, uint32_t val);
void stq_phys(target_phys_addr_t addr, uint64_t val);

void stl_phys_notdirty(target_phys_addr_t addr, uint32_t val);

#ifdef __cplusplus
}
#endif

#endif /* !CPU_COMMON_H */
