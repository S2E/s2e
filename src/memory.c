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

#include <assert.h>
#include <cpu/memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "exec-all.h"
#include "exec-ram.h"

#define DPRINTF(...)

static const unsigned MEM_REGION_MAX_COUNT = 32;
static MemoryDesc s_regions[MEM_REGION_MAX_COUNT];
static unsigned s_region_count = 0;

static bool get_memory_access_flags(uint64_t start, uint64_t size, bool *readable, bool *writable) {
    bool ret = false;
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        fprintf(stderr, "Could not open mem maps %s\n", __FUNCTION__);
        exit(-1);
    }

    char buffer[512];
    while (fgets(buffer, sizeof(buffer), fp)) {
        uint64_t s, e;
        char r, w;
        sscanf(buffer, "%" PRIx64 "-%" PRIx64 " %c%c", &s, &e, &r, &w);
        if (start >= s && ((start + size) <= e)) {

#ifdef SE_KVM_DEBUG_MEMORY
            printf("    Area %" PRIx64 "-%" PRIx64 " %c\n", s, e, w);
#endif

            *writable = w == 'w';
            *readable = r == 'r';
            ret = true;
            goto end;
        }
    }

    fprintf(stderr, "Could not execute %s\n", __FUNCTION__);
    exit(-1);

end:
    fclose(fp);
    return ret;
}

const MemoryDesc *mem_desc_register(struct kvm_userspace_memory_region *kr) {
    if (!kr->memory_size) {
        return NULL;
    }

    DPRINTF("%s: guest=%#llx size=%#llx\n", __FUNCTION__, kr->guest_phys_addr, kr->memory_size);

    assert(kr->slot < MEM_REGION_MAX_COUNT);

    bool readable, writable;
    get_memory_access_flags(kr->userspace_addr, kr->memory_size, &readable, &writable);

    bool ro = readable && !writable;

    // There shouldn't be any readonly regions, we don't support KVM_CAP_READONLY_MEM
    assert(!ro);

    MemoryDesc *r = &s_regions[kr->slot];
    r->kvm = *kr;
    r->read_only = ro;

    if (s_region_count < kr->slot + 1) {
        s_region_count = kr->slot + 1;
    }

    r->ram_addr = qemu_ram_alloc_from_ptr(kr->memory_size, (void *) kr->userspace_addr);

    return r;
}

///
/// \brief mem_desc_find
/// \param guest_phys_addr
/// \return null if there is no ram at this address, which means mmio
///
const MemoryDesc *mem_desc_find(uint64_t guest_phys_addr) {
    for (unsigned i = 0; i < s_region_count; ++i) {
        const MemoryDesc *r = &s_regions[i];
        if (!r->kvm.memory_size) {
            continue;
        }

        uint64_t a = r->kvm.guest_phys_addr;
        uint64_t b = a - 1 + r->kvm.memory_size;

        if (guest_phys_addr >= a && guest_phys_addr <= b) {
            return r;
        }
    }

    return NULL;
}

const MemoryDesc *mem_desc_get_slot(unsigned slot) {
    assert(slot < MEM_REGION_MAX_COUNT);
    return &s_regions[slot];
}

void mem_desc_unregister(unsigned slot) {
    // TODO: notify all listeners to reset their maps
    MemoryDesc *r = &s_regions[slot];
    if (!r->kvm.memory_size) {
        return;
    }

    qemu_ram_free_from_ptr(r->ram_addr);

    DPRINTF("%s: guest=%#llx size=%#llx\n", __FUNCTION__, r->kvm.guest_phys_addr, r->kvm.memory_size);

    memset(r, 0, sizeof(*r));
}

void *mem_desc_get_ram_ptr(const MemoryDesc *r) {
    return qemu_get_ram_ptr(r->ram_addr & TARGET_PAGE_MASK);
}
