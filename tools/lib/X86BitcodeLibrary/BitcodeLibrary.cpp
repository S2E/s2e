///
/// Copyright (C) 2015-2017, Cyberhaven
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
///

extern "C" {
#include <cpu-all.h>
#include <exec-all.h>
#include <qemu-common.h>
}

#include <stdio.h>
#include <sys/mman.h>

#include <BitcodeLibrary/Runtime.h>

//#define DEBUG_RUNTIME

#ifdef DEBUG_RUNTIME
#define dprintf(...) printf(__VA_ARGS__)
#else
#define dprintf(...)
#endif

#define min(a, b) ((a) < (b) ? (a) : (b))

extern "C" {
extern CPUArchState *env;
extern CPUArchState myenv;

/***********************************************************/
#define DECLARE_MMU_LD(T, sz, suffix) \
    T helper_ld##sz##_##suffix(CPUArchState *env, target_ulong addr, int mmu_idx, void *retaddr);

#define DECLARE_MMU_ST(T, sz, suffix) \
    void helper_st##sz##_##suffix(CPUArchState *env, target_ulong addr, T data, int mmu_idx, void *retaddr);

DECLARE_MMU_LD(uint8_t, b, mmu)
DECLARE_MMU_LD(uint16_t, w, mmu)
DECLARE_MMU_LD(uint32_t, l, mmu)
DECLARE_MMU_LD(uint64_t, q, mmu)

DECLARE_MMU_ST(uint8_t, b, mmu)
DECLARE_MMU_ST(uint16_t, w, mmu)
DECLARE_MMU_ST(uint32_t, l, mmu)
DECLARE_MMU_ST(uint64_t, q, mmu)

extern void *__qemu_ld_helpers[5] = {
    (void *) helper_ldb_mmu, (void *) helper_ldw_mmu, (void *) helper_ldl_mmu,
    (void *) helper_ldq_mmu, (void *) helper_ldq_mmu,
};

extern void *__qemu_st_helpers[5] = {
    (void *) helper_stb_mmu, (void *) helper_stw_mmu, (void *) helper_stl_mmu,
    (void *) helper_stq_mmu, (void *) helper_stq_mmu,
};

/***********************************************************/
#define DECLARE_MEM_LD(T, sz, suffix) T ld##sz##_##suffix(target_ulong addr);

DECLARE_MEM_LD(uint64_t, q, data)
DECLARE_MEM_LD(uint32_t, l, kernel)
DECLARE_MEM_LD(uint32_t, l, data)
DECLARE_MEM_LD(uint16_t, uw, kernel)
DECLARE_MEM_LD(uint16_t, uw, data)
DECLARE_MEM_LD(int16_t, sw, data)
DECLARE_MEM_LD(uint8_t, ub, kernel)
DECLARE_MEM_LD(uint8_t, ub, data)

/***********************************************************/

#define DECLARE_MEM_ST(T, sz, suffix) void st##sz##_##suffix(target_ulong addr, T data);

DECLARE_MEM_ST(uint64_t, q, data)
DECLARE_MEM_ST(uint32_t, l, kernel)
DECLARE_MEM_ST(uint32_t, l, data)
DECLARE_MEM_ST(int16_t, w, kernel)
DECLARE_MEM_ST(uint16_t, uw, kernel)
DECLARE_MEM_ST(int16_t, w, data)
DECLARE_MEM_ST(uint8_t, ub, kernel)
DECLARE_MEM_ST(int8_t, b, kernel)
DECLARE_MEM_ST(int8_t, b, data)

/***********************************************************/
#define DECLARE_MEM_PHYS_LD(T, sz, suffix) T ld##sz##_##suffix(target_phys_addr_t addr);

DECLARE_MEM_PHYS_LD(uint32_t, ub, phys)
DECLARE_MEM_PHYS_LD(uint32_t, uw, phys)
DECLARE_MEM_PHYS_LD(uint32_t, l, phys)
DECLARE_MEM_PHYS_LD(uint64_t, q, phys)

/**********************************/

uint64_t revgen_function_count;
revgen_function_t *revgen_function_pointers;
uint64_t *revgen_function_addresses;

void call_marker(target_ulong pc);
void incomplete_marker(target_ulong pc);
void revgen_trace(target_ulong pc);

/**********************************/

unsigned section_count;

uint8_t **section_ptrs;
uint64_t *section_vas;
uint64_t *section_sizes;

void helper_raise_interrupt(int intno, int next_eip_addend);

/**********************************/

/**
 * This ensures that functions are declared in the bitcode file.
 * Just having declarations is not enough.
 */
void ___fcndefs(void) {
    myenv.regs[R_EAX] = 0;
    revgen_entrypoint(&myenv);
    call_marker(0);
    revgen_trace(0);
    incomplete_marker(0);

    helper_raise_interrupt(0, 0);

    section_count = 0;
    section_ptrs = NULL;
    section_vas = NULL;
    section_sizes = NULL;
}
}
