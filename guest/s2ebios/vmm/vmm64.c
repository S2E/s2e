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

#include <inttypes.h>

#include "vmm.h"

#define PML4_SHIFT 39
#define PDP_SHIFT  30
#define PD_SHIFT   21
#define PT_SHIFT   12

#define PTRS_PER_TABLE 512
#define PAGE_SIZE      4096
#define PAGE_MASK      0xFFF

#define PML4_INDEX(x) (((x) >> PML4_SHIFT) & 0x1FF)
#define PDP_INDEX(x)  (((x) >> PDP_SHIFT) & 0x1FF)
#define PD_INDEX(x)   (((x) >> PD_SHIFT) & 0x1FF)
#define PT_INDEX(x)   (((x) >> PT_SHIFT) & 0x1FF)

static uint64_t *g_pml4e;
static uint64_t s_next_page = 0x100000;
static const uint64_t s_max_page = 0x200000;

static uint64_t get_next_page() {
    if (s_next_page >= s_max_page) {
        return 0;
    }

    uint64_t ret = s_next_page;
    s_next_page += 0x1000;
    return ret;
}

static uintptr_t read_cr3() {
    uintptr_t ret;
    __asm__ volatile("mov %%cr3, %0" : "=r"(ret));

    return ret;
}

void vmm_init() {
    g_pml4e = (uint64_t *) read_cr3();
}

int vmm_map_page(uint64_t virtual, uint64_t physical) {
    uint64_t *pdpt;
    uint64_t *pd;
    uint64_t *pt;

    // Fetch the PML4 entry.
    uint64_t *pml4e = &g_pml4e[PML4_INDEX(virtual)];

    if (!(*pml4e & 1)) { // If not present
        pdpt = (uint64_t *) get_next_page();
        if (!pdpt) {
            return -1;
        }

        *pml4e = (uint64_t) pdpt | 3; // Map it (set p and rw bits)
    } else {
        pdpt = (uint64_t *) (*pml4e & ~PAGE_MASK); // Extract the address
    }

    uint64_t *pdpte = &pdpt[PDP_INDEX(virtual)];

    if (!(*pdpte & 1)) {
        pd = (uint64_t *) get_next_page();
        if (!pd) {
            return -1;
        }

        *pdpte = (uint64_t) pd | 3;
    } else {
        pd = (uint64_t *) (*pdpte & ~PAGE_MASK);
    }

    uint64_t *pde = &pd[PD_INDEX(virtual)];

    if (!(*pde & 1)) {
        pt = (uint64_t *) get_next_page();
        if (!pt) {
            return -1;
        }

        *pde = (uint64_t) pt | 3;
    } else {
        pt = (uint64_t *) (*pde & ~PAGE_MASK);
    }

    // The final entry in the page table maps the virtual address to the physical one
    pt[PT_INDEX(virtual)] = (physical & ~PAGE_MASK) | 3;

    return 0;
}
