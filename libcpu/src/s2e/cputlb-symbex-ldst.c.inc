/// Copyright (C) 2026  Vitaly Chipounov
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

/// @file
/// Reports guest memory accesses to the S2E plugins.
///
/// accel/cputlb.c includes this file after the definitions of
/// do_{ld,st}{1,2,4,8,16}_mmu() and before the entry points that call them
/// (ldst_common.c.inc and the code fetch functions). The functions below wrap
/// them, and the macros at the end make the entry points call the wrappers.
/// The wrappers of the accesses of 1 to 8 bytes report the access. The
/// upstream functions are not edited.
///
/// The slow path only runs for the accesses that plugins want to see: when a
/// plugin subscribes to memory accesses, tlb_set_page_full() marks every page
/// with TLB_MEM_TRACE, which keeps generated code off the inline fast path.
///
/// Natively executed code reports an access after it happened, with its
/// value. Bitcode also reports it before, while the address can still be
/// symbolic. Bitcode reports accesses to symbolic hardware from the device
/// path instead (se_hw_ld_beN() and se_hw_st_leN() in cputlb-symbex.c.inc),
/// where the flags of the page are known.
///
/// In the bitcode build, the wrappers also do the accesses that hit the TLB
/// themselves (se_tlb_hit_haddr()), so that KLEE only interprets the upstream
/// access path for misses and flagged pages. With fork-on-symbolic-address,
/// the wrappers also make the address concrete, once per access and before
/// the TLB lookup, and pass the concrete address to the upstream path. The
/// wrappers of do_ld16_mmu() and do_st16_mmu() only do this. mmu_lookup()
/// therefore always gets a concrete address and does not concretize it.

#if defined(CONFIG_SYMBEX)

#if defined(SYMBEX_LLVM_LIB)

static inline void se_trace_before(vaddr addr, uint64_t value, unsigned size, unsigned flags) {
    if (*g_sqi.events.before_memory_access_signals_count) {
        tcg_llvm_before_memory_access(addr, value, size, flags);
    }
}

static inline void se_trace_after(vaddr addr, uint64_t value, unsigned size, unsigned flags) {
    if (*g_sqi.events.after_memory_access_signals_count) {
        tcg_llvm_after_memory_access(addr, value, size, flags, 0);
    }
}

/* With fork-on-symbolic-address, replaces a symbolic address by one of its
   values and forks the state on the others. */
static inline vaddr se_concrete_addr(vaddr addr) {
    if (*g_sqi.mode.fork_on_symbolic_address) {
        addr = tcg_llvm_fork_and_concretize(addr, 0, (target_ulong) -1, 0);
    }
    return addr;
}

/*
 * The TLB hit fast path of the bitcode build.
 *
 * In natively executed code, the TCG backend inlines the TLB hit check into
 * the generated code, and only a miss or a flagged page calls the helpers.
 * The LLVM translator calls the helpers for every access, so without this
 * function KLEE would interpret the whole upstream access path every time.
 *
 * The function handles the accesses that need nothing but the host address:
 * no byte swap, no alignment requirement, no page crossing, and a TLB entry
 * for the page with none of the upstream comparator flags. Device pages,
 * watchpoints, read-only pages and pages with symbolic hardware have flags in
 * slow_flags, which always set TLB_FORCE_SLOW in the comparator
 * (tlb_set_compare()). The S2E comparator flags are ignored, as in the
 * upstream path of the bitcode: KLEE handles symbolic data and shared
 * objects itself, and the wrappers below report the access.
 *
 * The caller makes the address concrete first (se_concrete_addr()).
 *
 * @return true if the caller can access the bytes at *haddr
 */
static inline bool se_tlb_hit_haddr(CPUState *cpu, vaddr addr, MemOpIdx oi, MMUAccessType type, void **haddr) {
    MemOp memop = get_memop(oi);
    int mmu_idx = get_mmuidx(oi);
    CPUTLBEntry *entry;
    uint64_t tlb_addr;

    if (memop & (MO_BSWAP | MO_AMASK)) {
        return false;
    }

    if ((addr & ~TARGET_PAGE_MASK) + memop_size(memop) > TARGET_PAGE_SIZE) {
        return false;
    }

    entry = tlb_entry(cpu, mmu_idx, addr);
    tlb_addr = tlb_read_idx(entry, type);
    if ((tlb_addr & (TARGET_PAGE_MASK | (TLB_FLAGS_MASK & ~TLB_SE_FLAGS_MASK))) != (addr & TARGET_PAGE_MASK)) {
        return false;
    }

    *haddr = (void *) ((uintptr_t) addr + entry->addend);
    return true;
}

/* 16-byte accesses are not reported and always take the upstream path. */
static Int128 se_do_ld16_mmu(CPUState *cpu, vaddr addr, MemOpIdx oi, uintptr_t ra) {
    return do_ld16_mmu(cpu, se_concrete_addr(addr), oi, ra);
}

static void se_do_st16_mmu(CPUState *cpu, vaddr addr, Int128 val, MemOpIdx oi, uintptr_t ra) {
    do_st16_mmu(cpu, se_concrete_addr(addr), val, oi, ra);
}

#define do_ld16_mmu se_do_ld16_mmu
#define do_st16_mmu se_do_st16_mmu

#else

#define se_trace_before(addr, value, size, flags) ((void) 0)
#define se_concrete_addr(addr)                    (addr)

static inline void se_trace_after(vaddr addr, uint64_t value, unsigned size, unsigned flags) {
#if defined(SE_ENABLE_MEM_TRACING)
    if (unlikely(*g_sqi.events.after_memory_access_signals_count)) {
        g_sqi.events.after_memory_access(addr, value, size, flags, 0);
    }
#endif
}

/* Natively executed code reaches the helpers only after the inline fast path
   of the generated code has failed. */
#define se_tlb_hit_haddr(cpu, addr, oi, type, haddr) false

#endif

/* Code fetches are not reported. ld_he and st_he access the host bytes in
   host byte order, which is the order of the accesses of the fast path. */
#define SE_GEN_LD(n, type, ld_he)                                                                               \
    static type se_do_ld##n##_mmu(CPUState *cpu, vaddr addr, MemOpIdx oi, uintptr_t ra, MMUAccessType access) { \
        type ret;                                                                                               \
        void *haddr;                                                                                            \
        if (access == MMU_INST_FETCH) {                                                                         \
            return do_ld##n##_mmu(cpu, se_concrete_addr(addr), oi, ra, access);                                 \
        }                                                                                                       \
        se_trace_before(addr, 0, n, 0);                                                                         \
        addr = se_concrete_addr(addr);                                                                          \
        if (se_tlb_hit_haddr(cpu, addr, oi, access, &haddr)) {                                                  \
            ret = ld_he(haddr);                                                                                 \
        } else {                                                                                                \
            ret = do_ld##n##_mmu(cpu, addr, oi, ra, access);                                                    \
        }                                                                                                       \
        se_trace_after(addr, ret, n, 0);                                                                        \
        return ret;                                                                                             \
    }

#define SE_GEN_ST(n, type, st_he)                                                                   \
    static void se_do_st##n##_mmu(CPUState *cpu, vaddr addr, type val, MemOpIdx oi, uintptr_t ra) { \
        void *haddr;                                                                                \
        se_trace_before(addr, val, n, MEM_TRACE_FLAG_WRITE);                                        \
        addr = se_concrete_addr(addr);                                                              \
        if (se_tlb_hit_haddr(cpu, addr, oi, MMU_DATA_STORE, &haddr)) {                              \
            st_he(haddr, val);                                                                      \
        } else {                                                                                    \
            do_st##n##_mmu(cpu, addr, val, oi, ra);                                                 \
        }                                                                                           \
        se_trace_after(addr, val, n, MEM_TRACE_FLAG_WRITE);                                         \
    }

SE_GEN_LD(1, uint8_t, ldub_p)
SE_GEN_LD(2, uint16_t, lduw_he_p)
SE_GEN_LD(4, uint32_t, ldl_he_p)
SE_GEN_LD(8, uint64_t, ldq_he_p)

SE_GEN_ST(1, uint8_t, stb_p)
SE_GEN_ST(2, uint16_t, stw_he_p)
SE_GEN_ST(4, uint32_t, stl_he_p)
SE_GEN_ST(8, uint64_t, stq_he_p)

#undef SE_GEN_LD
#undef SE_GEN_ST

#define do_ld1_mmu se_do_ld1_mmu
#define do_ld2_mmu se_do_ld2_mmu
#define do_ld4_mmu se_do_ld4_mmu
#define do_ld8_mmu se_do_ld8_mmu

#define do_st1_mmu se_do_st1_mmu
#define do_st2_mmu se_do_st2_mmu
#define do_st4_mmu se_do_st4_mmu
#define do_st8_mmu se_do_st8_mmu

#endif

#if defined(SYMBEX_LLVM_LIB)
/* Ends the region of inlined functions that cputlb-symbex.c.inc starts. */
#pragma clang attribute pop
#endif
