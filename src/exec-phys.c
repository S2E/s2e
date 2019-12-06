/// Copyright (C) 2003  Fabrice Bellard
/// Copyright (C) 2010  Dependable Systems Laboratory, EPFL
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

#include <cpu/config.h>
#include <cpu/memory.h>
#include <inttypes.h>

#include <tcg/utils/osdep.h>
#include "exec.h"
#include "qemu-common.h"

const uint16_t phys_section_unassigned = 0;
const uint16_t phys_section_notdirty = 1;
const uint16_t phys_section_rom = 2;
const uint16_t phys_section_watch = 3;

static const uint64_t phys_section_max_dummy = 4;

static struct MemoryDescOps s_memops[phys_section_max_dummy];

////////////////////////////////////////////////////////////////////////////////////////
/// Public functions

void phys_register_section(unsigned index, const struct MemoryDescOps *ops) {
    assert(index < phys_section_max_dummy);
    s_memops[index] = *ops;
}

const struct MemoryDescOps *phys_get_ops(target_phys_addr_t index) {
    unsigned idx = index & ~TARGET_PAGE_MASK;
    assert(idx < phys_section_max_dummy);
    return &s_memops[idx];
}

const MemoryDesc *phys_page_find(target_phys_addr_t index) {
    return mem_desc_find(index << TARGET_PAGE_BITS);
}

bool is_notdirty_ops(const struct MemoryDescOps *ops) {
    return &s_memops[phys_section_notdirty] == ops;
}
