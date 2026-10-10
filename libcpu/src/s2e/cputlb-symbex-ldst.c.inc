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
/// do_{ld,st}{1,2,4,8}_mmu() and before the entry points that call them
/// (ldst_common.c.inc and the code fetch functions). Each function below
/// wraps one of them and reports the access, and the macros at the end make
/// the entry points call the wrappers. The upstream functions are not edited.
///
/// The slow path only runs for the accesses that plugins want to see: when a
/// plugin subscribes to memory accesses, tlb_set_page_full() marks every page
/// with TLB_MEM_TRACE, which keeps generated code off the inline fast path.
///
/// Natively executed code reports an access after it happened, with its
/// value. Bitcode also reports it before, while the address can still be
/// symbolic, and reports accesses to symbolic hardware.

#if defined(CONFIG_SYMBEX)

#if defined(SYMBEX_LLVM_LIB)

static inline void se_trace_before(vaddr addr, uint64_t value, unsigned size, unsigned flags) {
    if (*g_sqi.events.before_memory_access_signals_count) {
        tcg_llvm_before_memory_access(addr, value, size, flags);
    }
}

/* Returns true if the first page of an access is a device or holds
   symbolic MMIO or DMA ranges. The access has just completed, so the page
   is in the TLB. */
static inline bool se_page_is_hw(CPUState *cpu, vaddr addr, MemOpIdx oi, MMUAccessType type) {
    int mmu_idx = get_mmuidx(oi);
    uintptr_t index = tlb_index(cpu, mmu_idx, addr);

    if (!tlb_hit(tlb_read_idx(tlb_entry(cpu, mmu_idx, addr), type), addr)) {
        return false;
    }
    return (cpu->neg.tlb.d[mmu_idx].fulltlb[index].slow_flags[type] & (TLB_MMIO | TLB_SYMB_MMIO)) != 0;
}

static inline void se_trace_after(CPUState *cpu, vaddr addr, MemOpIdx oi, uint64_t value, unsigned size,
                                  unsigned flags) {
    bool is_write = (flags & MEM_TRACE_FLAG_WRITE) != 0;

    if (*g_sqi.events.after_memory_access_signals_count) {
        tcg_llvm_after_memory_access(addr, value, size, flags, 0);
    }

    if (se_page_is_hw(cpu, addr, oi, is_write ? MMU_DATA_STORE : MMU_DATA_LOAD)) {
        tcg_llvm_trace_mmio_access(addr, value, size, is_write);
    }
}

#else

#define se_trace_before(addr, value, size, flags) ((void) 0)

static inline void se_trace_after(CPUState *cpu, vaddr addr, MemOpIdx oi, uint64_t value, unsigned size,
                                  unsigned flags) {
#if defined(SE_ENABLE_MEM_TRACING)
    if (unlikely(*g_sqi.events.after_memory_access_signals_count)) {
        g_sqi.events.after_memory_access(addr, value, size, flags, 0);
    }
#endif
}

#endif

/* Code fetches are not reported. */
#define SE_GEN_LD(n, type)                                                                                      \
    static type se_do_ld##n##_mmu(CPUState *cpu, vaddr addr, MemOpIdx oi, uintptr_t ra, MMUAccessType access) { \
        type ret;                                                                                               \
        if (access == MMU_INST_FETCH) {                                                                         \
            return do_ld##n##_mmu(cpu, addr, oi, ra, access);                                                   \
        }                                                                                                       \
        se_trace_before(addr, 0, n, 0);                                                                         \
        ret = do_ld##n##_mmu(cpu, addr, oi, ra, access);                                                        \
        se_trace_after(cpu, addr, oi, ret, n, 0);                                                               \
        return ret;                                                                                             \
    }

#define SE_GEN_ST(n, type)                                                                          \
    static void se_do_st##n##_mmu(CPUState *cpu, vaddr addr, type val, MemOpIdx oi, uintptr_t ra) { \
        se_trace_before(addr, val, n, MEM_TRACE_FLAG_WRITE);                                        \
        do_st##n##_mmu(cpu, addr, val, oi, ra);                                                     \
        se_trace_after(cpu, addr, oi, val, n, MEM_TRACE_FLAG_WRITE);                                \
    }

SE_GEN_LD(1, uint8_t)
SE_GEN_LD(2, uint16_t)
SE_GEN_LD(4, uint32_t)
SE_GEN_LD(8, uint64_t)

SE_GEN_ST(1, uint8_t)
SE_GEN_ST(2, uint16_t)
SE_GEN_ST(4, uint32_t)
SE_GEN_ST(8, uint64_t)

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
