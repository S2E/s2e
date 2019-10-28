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

#include <glib.h>
#include <stdio.h>
#include <sys/mman.h>

#include <cpu/config.h>
#include <tcg/utils/osdep.h>
#include "exec-ram.h"
#include "exec.h"
#include "qemu-common.h"

#include <tcg/utils/cutils.h>

RAMList ram_list;

static uint64_t s_ram_size;

static int64_t parse_ram_size(int argc, char **argv) {
    int found = 0;
    int id = 0;

    for (int i = 0; i < argc; ++i) {
        if (!strcmp(argv[i], "-m")) {
            ++found;
            id = ++i;
        }
    }

    if (found == 1) {
        int64_t value;
        char *end_str;

        value = strtosz(argv[id], &end_str);
        if (value < 0 || *end_str) {
            fprintf(stderr, "libcpu: invalid ram size: %s\n", optarg);
            goto end;
        }

        if (value != (uint64_t)(ram_addr_t) value) {
            fprintf(stderr, "libcpu: ram size too large\n");
            goto end;
        }

        return value;
    } else if (found > 1) {
        fprintf(stderr, "-m option should be specified only one time\n");
        goto end;
    }

end:
    return -1;
}

bool init_ram_size(int argc, char **argv) {
    int64_t value = parse_ram_size(argc, argv);
    if (value < 0) {
        value = 128 * 1024 * 1024;
    }

    s_ram_size = (uint64_t) value;

    size_t length = s_ram_size;
    // Extra buffer for video ram and other devices.
    // This is arbitrary, if it's not enough, execution will
    // abort later.
    length += 17 * 1024 * 1024;
    length >>= TARGET_PAGE_BITS;

    ram_list.phys_dirty_size = length;
    ram_list.phys_dirty = mmap(NULL, length, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (!ram_list.phys_dirty) {
        fprintf(stderr, "Could not allocate dirty bitmap\n");
        return false;
    }

    return true;
}

uint64_t get_ram_size(void) {
    return s_ram_size;
}

void *get_ram_list_phys_dirty(void) {
    return ram_list.phys_dirty;
}

uint64_t get_ram_list_phys_dirty_size(void) {
    return ram_list.phys_dirty_size;
}

static ram_addr_t find_ram_offset(ram_addr_t size) {
    if (ram_list.block_count == 0) {
        return 0;
    }

    ram_addr_t best_offset = RAM_ADDR_MAX;
    ram_addr_t best_size = RAM_ADDR_MAX;

    for (unsigned i = 0; i < ram_list.block_count; ++i) {
        const RAMBlock *b = &ram_list.blocks[i];

        bool first = (i == 0);
        bool last = (i == ram_list.block_count - 1);

        if (first) {
            if (b->offset >= size && size <= best_size) {
                best_offset = 0;
                best_size = b->offset;
            }
        }

        ram_addr_t next_gap = b->offset + b->length;
        ram_addr_t next_size = last ? RAM_ADDR_MAX - next_gap : (b + 1)->offset - next_gap;
        if (next_size < size) {
            /* We don't fit in the next available gap */
            continue;
        }

        if (next_size < best_size) {
            best_offset = next_gap;
            best_size = next_size;
        }
    }

    if (best_offset == RAM_ADDR_MAX) {
        fprintf(stderr, "libcpu: Failed to find a gap of the requested size: %u\n", (unsigned) size);
        exit(-1);
    }

    return best_offset;
}

ram_addr_t last_ram_offset(void) {
    ram_addr_t last = 0;

    if (ram_list.block_count > 0) {
        const RAMBlock *block = &ram_list.blocks[ram_list.block_count - 1];
        last = block->offset + block->length;
    }

    return last;
}

///
/// \brief ramblock_cmp is a comparator to sort ram blocks
/// by increasing offset.
///
/// \param a the first block
/// \param b the second block
/// \return -1 if a < b or +1 if a > b.
///
static int ramblock_cmp(const void *a, const void *b) {
    const RAMBlock *ra = (RAMBlock *) a;
    const RAMBlock *rb = (RAMBlock *) b;
    if (ra->offset + ra->length <= rb->offset) {
        return -1;
    } else if (ra->offset >= rb->offset + rb->length) {
        return 1;
    } else {
        /* We don't tolerate overlapping ranges */
        abort();
    }
}

///
/// \brief qemu_ram_alloc_from_ptr allocates a ram block
///
/// The ram block address is a fictive address that represents
/// a block of ram. The idea is that given such an address,
/// it is possible to determine the dirty status for any given page
/// of physical memory by a simple array lookup.
///
/// We want to keep the dirty bitmap fixed and as small as possible,
/// so we use best fit algorithm to allocate ram blocks.
///
/// \param size the size of the block
/// \param host the host address of the block
/// \return the ram block address
///
ram_addr_t qemu_ram_alloc_from_ptr(ram_addr_t size, void *host) {
    assert(host);

    size = TARGET_PAGE_ALIGN(size);
    ram_addr_t new_offset = find_ram_offset(size);

    ram_list.block_count++;
    ram_list.blocks = g_realloc(ram_list.blocks, ram_list.block_count * sizeof(RAMBlock));
    RAMBlock *new_block = &ram_list.blocks[ram_list.block_count - 1];

    new_block->offset = new_offset;
    new_block->host = host;
    new_block->length = size;

    /* new_block ptr becomes invalid after qsort */
    qsort(ram_list.blocks, ram_list.block_count, sizeof(RAMBlock), ramblock_cmp);

    if (!ram_list.phys_dirty_size) {
        ram_list.phys_dirty = g_realloc(ram_list.phys_dirty, last_ram_offset() >> TARGET_PAGE_BITS);
    } else {
        // This is a special mode that pre-allocates a static dirty bitmap before
        // execution starts. Useful for symbolic execution engines that don't support
        // dynamic reallocation of memory.
        assert(ram_list.phys_dirty);
        if ((last_ram_offset() >> TARGET_PAGE_BITS) > ram_list.phys_dirty_size) {
            fprintf(stderr, "Not enough space in dirty bitmap\n");
            abort();
        }
    }

    memset(ram_list.phys_dirty + (new_offset >> TARGET_PAGE_BITS), 0xff, size >> TARGET_PAGE_BITS);

    return new_offset;
}

void qemu_ram_free_from_ptr(ram_addr_t addr) {
    for (unsigned i = 0; i < ram_list.block_count; ++i) {
        RAMBlock *block = &ram_list.blocks[i];
        if (block->offset == addr) {
            memmove(block, block + 1, (ram_list.block_count - i - 1) * sizeof(RAMBlock));
            ram_list.block_count--;
            return;
        }
    }
}

static void print_ram_blocks(void) {
    fprintf(stderr, "phys_dirty: %p  phys_dirty_size: %lx\n", ram_list.phys_dirty, ram_list.phys_dirty_size);

    for (unsigned i = 0; i < ram_list.block_count; ++i) {
        RAMBlock *block = &ram_list.blocks[i];
        fprintf(stderr, "host=%p offset=%#lx length=%lx\n", block->host, block->offset, block->length);
    }
}

/* Return a host pointer to ram allocated with qemu_ram_alloc.
   With the exception of the softmmu code in this file, this should
   only be used for local memory (e.g. video ram) that the device owns,
   and knows it isn't going to access beyond the end of the block.

   It should not be used for general purpose DMA.
   Use cpu_physical_memory_map/cpu_physical_memory_rw instead.
 */

void *get_ram_ptr_internal(ram_addr_t addr) {
    for (unsigned i = 0; i < ram_list.block_count; ++i) {
        RAMBlock *block = &ram_list.blocks[i];
        if (addr - block->offset < block->length) {
            // XXX: somehow move this to the front
            return block->host + (addr - block->offset);
        }
    }

    return NULL;
}

void *qemu_get_ram_ptr(ram_addr_t addr) {
    void *ret = get_ram_ptr_internal(addr);
    if (ret) {
        return ret;
    }

    fprintf(stderr, "Bad ram offset %" PRIx64 "\n", (uint64_t) addr);
    print_ram_blocks();
    abort();

    return NULL;
}

// XXX: looks like the same as qemu_get_ram_ptr
// TODO: remove qemu_ prefix from these functions

/* Return a host pointer to ram allocated with qemu_ram_alloc.
 * Same as qemu_get_ram_ptr but avoid reordering ramblocks.
 */
void *qemu_safe_ram_ptr(ram_addr_t addr) {
    for (unsigned i = 0; i < ram_list.block_count; ++i) {
        RAMBlock *block = &ram_list.blocks[i];

        if (addr - block->offset < block->length) {
            return block->host + (addr - block->offset);
        }
    }

    fprintf(stderr, "Bad ram offset %" PRIx64 "\n", (uint64_t) addr);
    print_ram_blocks();
    abort();

    return NULL;
}

/* Return a host pointer to guest's ram. Similar to qemu_get_ram_ptr
 * but takes a size argument */
void *qemu_ram_ptr_length(ram_addr_t addr, ram_addr_t *size) {
    if (*size == 0) {
        return NULL;
    }

    for (unsigned i = 0; i < ram_list.block_count; ++i) {
        RAMBlock *block = &ram_list.blocks[i];

        if (addr - block->offset < block->length) {
            if (addr - block->offset + *size > block->length)
                *size = block->length - addr + block->offset;
            return block->host + (addr - block->offset);
        }
    }

    fprintf(stderr, "Bad ram offset %" PRIx64 "\n", (uint64_t) addr);
    abort();
}

void qemu_put_ram_ptr(void *addr) {
    // trace_qemu_put_ram_ptr(addr);
}

int qemu_ram_addr_from_host(void *ptr, ram_addr_t *ram_addr) {
    uint8_t *host = ptr;

    for (unsigned i = 0; i < ram_list.block_count; ++i) {
        RAMBlock *block = &ram_list.blocks[i];

        /* This case append when the block is not mapped. */
        if (block->host == NULL) {
            continue;
        }
        if (host - block->host < block->length) {
            *ram_addr = block->offset + (host - block->host);
            return 0;
        }
    }

    return -1;
}

/* Some of the softmmu routines need to translate from a host pointer
   (typically a TLB entry) back to a ram offset.  */
ram_addr_t qemu_ram_addr_from_host_nofail(void *ptr) {
    ram_addr_t ram_addr;

    if (qemu_ram_addr_from_host(ptr, &ram_addr)) {
        fprintf(stderr, "Bad ram pointer %p\n", ptr);
        abort();
    }
    return ram_addr;
}

void cpu_physical_memory_get_dirty_bitmap(uint8_t *bitmap, ram_addr_t start, int length, int dirty_flags) {
    int i, len;
    uint8_t *p;
    ram_addr_t end = TARGET_PAGE_ALIGN(start + length);
    len = (end - start) >> TARGET_PAGE_BITS;
    p = ram_list.phys_dirty + (start >> TARGET_PAGE_BITS);
    for (i = 0; i < len; i++) {
        int df;
#if defined(CONFIG_SYMBEX_MP)
        df = se_read_dirty_mask_fast((uint64_t) &p[i]) & dirty_flags;
#else
        df = *p++ & dirty_flags;
#endif

        if (df) {
            bitmap[i / 8] |= 1 << (i % 8);
        }
    }
}
