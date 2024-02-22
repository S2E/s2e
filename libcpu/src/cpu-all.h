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

#ifndef CPU_ALL_H
#define CPU_ALL_H

#include <cpu/cpu-common.h>
#include <cpu/exec.h>
#include <cpu/i386/cpu.h>
#include <tcg/cpu.h>
#include <tcg/utils/bswap.h>
#include "qemu-common.h"

#ifdef CONFIG_SYMBEX
#include <cpu/se_libcpu.h>
#include <cpu/se_libcpu_config.h>
#endif

/* CPU memory access without any memory or io remapping */

/*
 * the generic syntax for the memory accesses is:
 *
 * load: ld{type}{sign}{size}{endian}_{access_type}(ptr)
 *
 * store: st{type}{size}{endian}_{access_type}(ptr, val)
 *
 * type is:
 * (empty): integer access
 *   f    : float access
 *
 * sign is:
 * (empty): for floats or 32 bit size
 *   u    : unsigned
 *   s    : signed
 *
 * size is:
 *   b: 8 bits
 *   w: 16 bits
 *   l: 32 bits
 *   q: 64 bits
 *
 * endian is:
 * (empty): target cpu endianness or 8 bit access
 *   r    : reversed target cpu endianness (not implemented yet)
 *   be   : big endian (not implemented yet)
 *   le   : little endian (not implemented yet)
 *
 * access_type is:
 *   raw    : host memory access
 *   user   : user mode access using soft MMU
 *   kernel : kernel mode access using soft MMU
 */

/* target-endianness CPU memory access functions */
#if defined(TARGET_WORDS_BIGENDIAN)
#define lduw_p(p)    lduw_be_p(p)
#define ldsw_p(p)    ldsw_be_p(p)
#define ldl_p(p)     ldl_be_p(p)
#define ldq_p(p)     ldq_be_p(p)
#define ldfl_p(p)    ldfl_be_p(p)
#define ldfq_p(p)    ldfq_be_p(p)
#define stw_p(p, v)  stw_be_p(p, v)
#define stl_p(p, v)  stl_be_p(p, v)
#define stq_p(p, v)  stq_be_p(p, v)
#define stfl_p(p, v) stfl_be_p(p, v)
#define stfq_p(p, v) stfq_be_p(p, v)
#else
#define lduw_p(p)    lduw_le_p(p)
#define ldsw_p(p)    ldsw_le_p(p)
#define ldl_p(p)     ldl_le_p(p)
#define ldq_p(p)     ldq_le_p(p)
#define ldfl_p(p)    ldfl_le_p(p)
#define ldfq_p(p)    ldfq_le_p(p)
#define stw_p(p, v)  stw_le_p(p, v)
#define stl_p(p, v)  stl_le_p(p, v)
#define stq_p(p, v)  stq_le_p(p, v)
#define stfl_p(p, v) stfl_le_p(p, v)
#define stfq_p(p, v) stfq_le_p(p, v)
#endif

/* MMU memory access macros */

/* NOTE: we use double casts if pointers and target_ulong have
   different sizes */
#define saddr(x) (uint8_t *) (long) (x)
#define laddr(x) (uint8_t *) (long) (x)

#if !defined(CONFIG_SYMBEX) || defined(SYMBEX_LLVM_LIB)

#define ldub_raw(p)    ldub_p(laddr((p)))
#define ldsb_raw(p)    ldsb_p(laddr((p)))
#define lduw_raw(p)    lduw_p(laddr((p)))
#define ldsw_raw(p)    ldsw_p(laddr((p)))
#define ldl_raw(p)     ldl_p(laddr((p)))
#define ldq_raw(p)     ldq_p(laddr((p)))
#define ldfl_raw(p)    ldfl_p(laddr((p)))
#define ldfq_raw(p)    ldfq_p(laddr((p)))
#define stb_raw(p, v)  stb_p(saddr((p)), v)
#define stw_raw(p, v)  stw_p(saddr((p)), v)
#define stl_raw(p, v)  stl_p(saddr((p)), v)
#define stq_raw(p, v)  stq_p(saddr((p)), v)
#define stfl_raw(p, v) stfl_p(saddr((p)), v)
#define stfq_raw(p, v) stfq_p(saddr((p)), v)

#define lduw_le_raw(p)    lduw_le_p(laddr((p)))
#define ldsw_le_raw(p)    ldsw_le_p(laddr((p)))
#define ldl_le_raw(p)     ldl_le_p(laddr((p)))
#define ldq_le_raw(p)     ldq_le_p(laddr((p)))
#define ldfl_le_raw(p)    ldfl_le_p(laddr((p)))
#define ldfq_le_raw(p)    ldfq_le_p(laddr((p)))
#define stb_le_raw(p, v)  stb_le_p(saddr((p)), v)
#define stw_le_raw(p, v)  stw_le_p(saddr((p)), v)
#define stl_le_raw(p, v)  stl_le_p(saddr((p)), v)
#define stq_le_raw(p, v)  stq_le_p(saddr((p)), v)
#define stfl_le_raw(p, v) stfl_le_p(saddr((p)), v)
#define stfq_le_raw(p, v) stfq_le_p(saddr((p)), v)

#define lduw_be_raw(p)    lduw_be_p(laddr((p)))
#define ldsw_be_raw(p)    ldsw_be_p(laddr((p)))
#define ldl_be_raw(p)     ldl_be_p(laddr((p)))
#define ldq_be_raw(p)     ldq_be_p(laddr((p)))
#define ldfl_be_raw(p)    ldfl_be_p(laddr((p)))
#define ldfq_be_raw(p)    ldfq_be_p(laddr((p)))
#define stb_be_raw(p, v)  stb_be_p(saddr((p)), v)
#define stw_be_raw(p, v)  stw_be_p(saddr((p)), v)
#define stl_be_raw(p, v)  stl_be_p(saddr((p)), v)
#define stq_be_raw(p, v)  stq_be_p(saddr((p)), v)
#define stfl_be_raw(p, v) stfl_be_p(saddr((p)), v)
#define stfq_be_raw(p, v) stfq_be_p(saddr((p)), v)

#else /* CONFIG_SYMBEX */

static inline int _se_check_concrete(void *objectState, target_ulong offset, int size) {
#if 1
    // The concrete mask is always non-null because of page splitting
    // XXX: We can safely remove the check.
    if (unlikely(*(uint8_t ***) objectState)) {
        uint8_t *bits = **(uint8_t ***) objectState;
        int mask = (1 << size) - 1;
        if (likely((offset & 7) + size <= 8)) {
            return ((((uint8_t *) (bits + (offset >> 3)))[0] >> (offset & 7)) & mask) == mask;
        } else {
            return ((((uint16_t *) (bits + (offset >> 3)))[0] >> (offset & 7)) & mask) == mask;
        }
    }
    return 1;
#else
    return 0;
#endif
}

static inline void *_se_check_translate_ram_access(const void *p, unsigned size) {
#if defined(SE_ENABLE_PHYSRAM_TLB)
    extern CPUArchState *env;
    uintptr_t tlb_index = ((uintptr_t) p >> 12) & (CPU_TLB_SIZE - 1);
    CPUTLBRAMEntry *re = &env->se_ram_tlb[tlb_index];
    if (re->host_page == (((uintptr_t) p) & (~(uintptr_t) 0xfff | (size - 1)))) {
        return (void *) ((uintptr_t) p + re->addend);
    }
#endif
    return NULL;
}

/* Functions suffixed with symb abort execution if it is in concrete mode */

/* host endianness */
#define _symbex_define_ld_raw(ct, t, s)                                \
    static inline ct ld##t##_raw(const void *p) {                      \
        const void *translated = _se_check_translate_ram_access(p, s); \
        if (translated) {                                              \
            return ld##t##_p(translated);                              \
        }                                                              \
        uint8_t buf[s];                                                \
        g_sqi.mem.read_ram_concrete((uint64_t) p, buf, s);             \
        return ld##t##_p(buf); /* read right type of value from buf */ \
    }                                                                  \
    static inline ct ld##t##_raw_symb(const void *p) {                 \
        uint8_t buf[s];                                                \
        g_sqi.mem.read_ram_concrete_check((uint64_t) p, buf, s);       \
        return ld##t##_p(buf);                                         \
    }

/* explicit little endian */
#define _symbex_define_ld_raw_le(ct, t, s)                                \
    static inline ct ld##t##_le_raw(const void *p) {                      \
        uint8_t buf[s];                                                   \
        g_sqi.mem.read_ram_concrete((uint64_t) p, buf, s);                \
        return ld##t##_le_p(buf); /* read right type of value from buf */ \
    }                                                                     \
    static inline ct ld##t##_le_raw_symb(const void *p) {                 \
        uint8_t buf[s];                                                   \
        g_sqi.mem.read_ram_concrete_check((uint64_t) p, buf, s);          \
        return ld##t##_le_p(buf);                                         \
    }

/* explicit big endian */
#define _symbex_define_ld_raw_be(ct, t, s)                                \
    static inline ct ld##t##_be_raw(const void *p) {                      \
        uint8_t buf[s];                                                   \
        g_sqi.mem.read_ram_concrete((uint64_t) p, buf, s);                \
        return ld##t##_be_p(buf); /* read right type of value from buf */ \
    }                                                                     \
    static inline ct ld##t##_be_raw_symb(const void *p) {                 \
        uint8_t buf[s];                                                   \
        g_sqi.mem.read_ram_concrete_check((uint64_t) p, buf, s);          \
        return ld##t##_be_p(buf);                                         \
    }

/* host endianness */
#define _symbex_define_st_raw(ct, t, s)                          \
    static inline void st##t##_raw(void *p, ct v) {              \
        void *translated = _se_check_translate_ram_access(p, s); \
        if (translated) {                                        \
            st##t##_p(translated, v);                            \
            return;                                              \
        }                                                        \
        uint8_t buf[s];                                          \
        st##t##_p(buf, v);                                       \
        g_sqi.mem.write_ram_concrete((uint64_t) p, buf, s);      \
    }                                                            \
    static inline void st##t##_raw_symb(void *p, ct v) {         \
        st##t##_raw(p, v);                                       \
    }

/* explicit little endian */
#define _symbex_define_st_raw_le(ct, t, s)                  \
    static inline void st##t##_le_raw(void *p, ct v) {      \
        uint8_t buf[s];                                     \
        st##t##_le_p(buf, v);                               \
        g_sqi.mem.write_ram_concrete((uint64_t) p, buf, s); \
    }                                                       \
    static inline void st##t##_le_raw_symb(void *p, ct v) { \
        st##t##_le_raw(p, v);                               \
    }

/* explicit big endian */
#define _symbex_define_st_raw_be(ct, t, s)                  \
    static inline void st##t##_be_raw(void *p, ct v) {      \
        uint8_t buf[s];                                     \
        st##t##_be_p(buf, v);                               \
        g_sqi.mem.write_ram_concrete((uint64_t) p, buf, s); \
    }                                                       \
    static inline void st##t##_be_raw_symb(void *p, ct v) { \
        st##t##_be_raw(p, v);                               \
    }

// clang-format off
_symbex_define_ld_raw(int, ub, 1)
_symbex_define_ld_raw(int, sb, 1)
_symbex_define_ld_raw(int, uw, 2)
_symbex_define_ld_raw(int, sw, 2)
_symbex_define_ld_raw(int,  l, 4)
_symbex_define_ld_raw(uint64_t,  q, 8)
_symbex_define_ld_raw(float32,  fl, 4)
_symbex_define_ld_raw(float64,  fq, 8)

_symbex_define_st_raw(int, b, 1)
_symbex_define_st_raw(int, w, 2)
_symbex_define_st_raw(int, l, 4)
_symbex_define_st_raw(uint64_t,  q, 8)
_symbex_define_st_raw(float32,  fl, 4)
_symbex_define_st_raw(float64,  fq, 8)

_symbex_define_ld_raw_le(int, uw, 2)
_symbex_define_ld_raw_le(int, sw, 2)
_symbex_define_ld_raw_le(int,  l, 4)
_symbex_define_ld_raw_le(uint64_t,  q, 8)
_symbex_define_ld_raw_le(float32,  fl, 4)
_symbex_define_ld_raw_le(float64,  fq, 8)

_symbex_define_st_raw_le(int, w, 2)
_symbex_define_st_raw_le(int, l, 4)
_symbex_define_st_raw_le(uint64_t,  q, 8)
_symbex_define_st_raw_le(float32,  fl, 4)
_symbex_define_st_raw_le(float64,  fq, 8)
// clang-format on
#endif

#define CPU_DUMP_CODE 0x00010000

static inline void cpu_interrupt(CPUArchState *s, int mask) {
    cpu_interrupt_handler(s, mask);
}

void cpu_reset_interrupt(CPUArchState *env, int mask);

/* Breakpoint/watchpoint flags */
#define BP_MEM_READ           0x01
#define BP_MEM_WRITE          0x02
#define BP_MEM_ACCESS         (BP_MEM_READ | BP_MEM_WRITE)
#define BP_STOP_BEFORE_ACCESS 0x04
#define BP_WATCHPOINT_HIT     0x08
#define BP_GDB                0x10
#define BP_CPU                0x20

int cpu_breakpoint_insert(CPUArchState *env, target_ulong pc, int flags, CPUBreakpoint **breakpoint);
int cpu_breakpoint_remove(CPUArchState *env, target_ulong pc, int flags);
void cpu_breakpoint_remove_by_ref(CPUArchState *env, CPUBreakpoint *breakpoint);
void cpu_breakpoint_remove_all(CPUArchState *env, int mask);
int cpu_watchpoint_insert(CPUArchState *env, target_ulong addr, target_ulong len, int flags,
                          CPUWatchpoint **watchpoint);
int cpu_watchpoint_remove(CPUArchState *env, target_ulong addr, target_ulong len, int flags);
void cpu_watchpoint_remove_by_ref(CPUArchState *env, CPUWatchpoint *watchpoint);
void cpu_watchpoint_remove_all(CPUArchState *env, int mask);

#define SSTEP_ENABLE  0x1 /* Enable simulated HW single stepping */
#define SSTEP_NOIRQ   0x2 /* Do not use IRQ while single stepping */
#define SSTEP_NOTIMER 0x4 /* Do not Timers while single stepping */

void cpu_single_step(CPUArchState *env, int enabled);
void cpu_state_reset(CPUArchState *s);
void run_on_cpu(CPUArchState *env, void (*func)(void *data), void *data);

/* Get a list of mapped pages. */
void list_mapped_pages(CPUX86State *env, unsigned rw_only, unsigned user_only, target_ulong **pages_addr,
                       size_t *pages_count);

#endif /* CPU_ALL_H */
