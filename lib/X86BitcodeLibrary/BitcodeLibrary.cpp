///
/// Copyright (C) 2015-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
#define DECLARE_MMU_LD(T, sz, suffix) T __ld##sz##_##suffix(target_ulong addr, int mmu_idx);

#define DECLARE_MMU_ST(T, sz, suffix) void __st##sz##_##suffix(target_ulong addr, T data, int mmu_idx);

DECLARE_MMU_LD(uint8_t, b, mmu)
DECLARE_MMU_LD(uint16_t, w, mmu)
DECLARE_MMU_LD(uint32_t, l, mmu)
DECLARE_MMU_LD(uint64_t, q, mmu)

DECLARE_MMU_ST(uint8_t, b, mmu)
DECLARE_MMU_ST(uint16_t, w, mmu)
DECLARE_MMU_ST(uint32_t, l, mmu)
DECLARE_MMU_ST(uint64_t, q, mmu)

extern void *__qemu_ld_helpers[5] = {
    (void *) __ldb_mmu, (void *) __ldw_mmu, (void *) __ldl_mmu, (void *) __ldq_mmu, (void *) __ldq_mmu,
};

extern void *__qemu_st_helpers[5] = {
    (void *) __stb_mmu, (void *) __stw_mmu, (void *) __stl_mmu, (void *) __stq_mmu, (void *) __stq_mmu,
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
    revgen_entrypoint();
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
