/// Copyright (C) 2018  Cyberhaven
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

#ifndef __LIBCPU_MEMDBG_H__

#define __LIBCPU_MEMDBG_H__

#include <cpu/config.h>
#include <cpu/i386/cpu.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

void cpu_host_memory_rw(uintptr_t source, uintptr_t dest, int length, int is_write);
int cpu_memory_rw_debug(void *opaque_env, target_ulong addr, uint8_t *buf, int len, int is_write);
void cpu_physical_memory_rw(target_phys_addr_t addr, uint8_t *buf, int len, int is_write);

#ifdef __cplusplus
}
#endif

#endif
