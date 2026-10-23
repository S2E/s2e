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
/// The symbolic execution cases of the softmmu lookup.
///
/// accel/cputlb.c includes this file after the definition of
/// MMULookupLocals, and mmu_lookup() calls se_mmu_resolve() once it has
/// translated the page or pages of an access.
///
/// A page can need attention for three reasons, which the TLB flags tell
/// apart (cpu/exec/tlb-flags.h):
///
///  - TLB_SYMB: the page holds symbolic data. Natively executed code can
///    only handle concrete bytes.
///  - TLB_NOT_OURS: the KLEE object that backs the page is shared with
///    another execution state and must be copied before it is written.
///  - TLB_MMIO and TLB_SYMB_MMIO: the access may hit a device register or a
///    DMA range that a plugin declared symbolic.
///
/// se_mmu_resolve() either leaves for symbolic execution, or decides how
/// natively executed code reaches the bytes of each page: directly, through
/// the host address that mmu_lookup() computed, or through libs2ecore. For
/// the second case it sets TLB_MMIO in the flags of the lookup result. This
/// is a local copy of the flags, the TLB is not changed. The upstream load
/// and store code already sends every access to a page with TLB_MMIO to
/// do_ld_mmio_beN() or do_st_mmio_leN(), with the value for a store. These
/// two functions call se_ram_ld_beN() and se_ram_st_leN() below, which do
/// the access through libs2ecore when the page is RAM. The upstream load and
/// store functions therefore need no S2E change, and no state is kept
/// between the lookup and the access. In the bitcode build, se_mmu_resolve()
/// only routes the accesses to symbolic hardware, which are reported to the
/// plugins.
///
/// The file also replaces the atomic load and store primitives of
/// ldst_atomicity.c.inc in builds with symbolic execution, and makes the
/// bitcode build inline the load and store path (see the end of the file).

#if defined(CONFIG_SYMBEX)

/*
 * The upstream primitives give an access the atomicity that its instruction
 * promises to other vCPUs. An unaligned load does this by reading the 16
 * aligned bytes around the address, relying on the host page offset of the
 * pointer to stay inside the page. This does not hold for a KLEE concrete
 * buffer, which is a 4096-byte heap block with no particular alignment: the
 * load could read past its end. In bitcode, the alignment test is a branch on
 * a possibly symbolic pointer and makes KLEE fork for no reason. libcpu has
 * one vCPU, so plain loads and stores of the exact size are enough.
 */

static inline Int128 se_ld16_he_p(const void *ptr) {
    Int128 r;
    __builtin_memcpy(&r, ptr, sizeof(r));
    return r;
}

static inline void se_st16_he_p(void *ptr, Int128 v) {
    __builtin_memcpy(ptr, &v, sizeof(v));
}

#define load_atom_2(cpu, ra, pv, memop)  lduw_he_p(pv)
#define load_atom_4(cpu, ra, pv, memop)  ((uint32_t) ldl_he_p(pv))
#define load_atom_8(cpu, ra, pv, memop)  ldq_he_p(pv)
#define load_atom_16(cpu, ra, pv, memop) se_ld16_he_p(pv)

#define store_atom_2(cpu, ra, pv, memop, val)  stw_he_p(pv, val)
#define store_atom_4(cpu, ra, pv, memop, val)  stl_he_p(pv, val)
#define store_atom_8(cpu, ra, pv, memop, val)  stq_he_p(pv, val)
#define store_atom_16(cpu, ra, pv, memop, val) se_st16_he_p(pv, val)

#endif

#if defined(CONFIG_SYMBEX) && defined(CONFIG_SYMBEX_MP) && !defined(SYMBEX_LLVM_LIB)

#define SE_RESOLVE_FLAGS (TLB_SYMB | TLB_NOT_OURS | TLB_MMIO | TLB_SYMB_MMIO)

/* Returns true if the accessed bytes of a RAM page are all concrete. */
static inline bool se_page_bytes_concrete(const MMULookupPageData *p) {
    void *object_state = p->full->extra.object_state;

    return !object_state || _se_check_concrete(object_state, p->addr & ~SE_RAM_OBJECT_MASK, p->size);
}

/*
 * First pass over one page of an access: leave for symbolic execution if
 * natively executed code cannot do the access.
 *
 * switch_to_symbolic() does not return: KLEE executes the whole instruction
 * again. Only generated code can switch. A helper may already have changed
 * the CPU state, which cannot be rolled back.
 */
static void se_mmu_check_page(MMULookupPageData *p, MMUAccessType type, uintptr_t ra) {
    if (!p->size || !(p->flags & SE_RESOLVE_FLAGS)) {
        return;
    }

    if (p->flags & (TLB_MMIO | TLB_SYMB_MMIO)) {
        /* A device model can only be given concrete values. */
        hwaddr paddr = p->full->phys_addr | (p->addr & ~TARGET_PAGE_MASK);
        if (g_sqi.mem.is_mmio_symbolic(paddr, p->size)) {
            g_sqi.exec.switch_to_symbolic((void *) ra);
        }
    }

    if (!(p->flags & TLB_MMIO) && type != MMU_DATA_STORE && !se_page_bytes_concrete(p)) {
        g_sqi.exec.switch_to_symbolic((void *) ra);
    }
}

/*
 * Second pass: decide whether the access to a RAM page can go directly to
 * the concrete buffer of its KLEE object, at haddr.
 *
 * It cannot in two cases. A store to a shared object must first make KLEE
 * copy the object. A load or a store that touches symbolic bytes must go
 * through KLEE, which concretizes the bytes of a load and records that a
 * store made them concrete. Both are done by libs2ecore, at the time of the
 * access (se_ram_ld_beN() and se_ram_st_leN()).
 */
static void se_mmu_resolve_page(MMULookupPageData *p, MMUAccessType type) {
    if (!p->size || !(p->flags & SE_RESOLVE_FLAGS) || (p->flags & TLB_MMIO)) {
        return;
    }

    bool direct = se_page_bytes_concrete(p);
    if (type == MMU_DATA_STORE && (p->flags & TLB_NOT_OURS)) {
        direct = false;
    }

    if (!direct) {
        p->flags |= TLB_MMIO;
    }
}

static inline void se_mmu_resolve(CPUState *cpu, MMULookupLocals *l, MMUAccessType type, uintptr_t ra) {
    if (likely(!((l->page[0].flags | l->page[1].flags) & SE_RESOLVE_FLAGS))) {
        return;
    }

    if (tcg_is_dyngen_addr((void *) ra)) {
        se_mmu_check_page(&l->page[0], type, ra);
        se_mmu_check_page(&l->page[1], type, ra);
    }

    se_mmu_resolve_page(&l->page[0], type);
    se_mmu_resolve_page(&l->page[1], type);
}

/* Returns the address of a guest byte in the guest RAM as QEMU mapped it.
   KLEE binds the object of the page at this address, and libs2ecore takes it
   as argument. haddr is a different address: it points into the concrete
   buffer of the object. */
static inline uintptr_t se_host_ram_addr(CPUState *cpu, vaddr addr, int mmu_idx) {
    return addr + tlb_entry(cpu, mmu_idx, addr)->addend;
}

/*
 * Loads size bytes of a RAM page through libs2ecore, which picks concrete
 * values for the symbolic ones and constrains the state accordingly.
 * do_ld_mmio_beN() calls it first.
 *
 * @param ret_be the bytes are appended to it, most significant first
 * @return false if the page is not RAM; the caller then reads the device
 */
static inline bool se_ram_ld_beN(CPUState *cpu, CPUTLBEntryFull *full, uint64_t *ret_be, vaddr addr, int size,
                                 int mmu_idx) {
    uint8_t buf[8];

    if (!memory_region_is_ram(full->section->mr)) {
        return false;
    }

    g_sqi.mem.read_ram_concrete(se_host_ram_addr(cpu, addr, mmu_idx), buf, size);
    for (int i = 0; i < size; i++) {
        *ret_be = (*ret_be << 8) | buf[i];
    }
    return true;
}

/*
 * Stores the low size bytes of a value to a RAM page through libs2ecore,
 * which makes KLEE copy the object if it is shared and marks the bytes
 * concrete. do_st_mmio_leN() calls it first.
 *
 * @param val_le the bytes are taken from it, least significant first, and
 *        shifted out
 * @return false if the page is not RAM; the caller then writes the device
 */
static inline bool se_ram_st_leN(CPUState *cpu, CPUTLBEntryFull *full, uint64_t *val_le, vaddr addr, int size,
                                 int mmu_idx) {
    uint8_t buf[8];

    if (!memory_region_is_ram(full->section->mr)) {
        return false;
    }

    for (int i = 0; i < size; i++) {
        buf[i] = *val_le;
        *val_le >>= 8;
    }
    g_sqi.mem.write_ram_concrete(se_host_ram_addr(cpu, addr, mmu_idx), buf, size);
    return true;
}

#elif defined(CONFIG_SYMBEX) && defined(SYMBEX_LLVM_LIB)

/*
 * The bitcode build. KLEE handles symbolic data and copies shared objects
 * itself, so the only S2E case left is symbolic hardware: the accesses to a
 * device page (TLB_MMIO) or to a RAM page with symbolic MMIO or DMA ranges
 * (TLB_SYMB_MMIO) are reported to libs2ecore with
 * tcg_llvm_trace_mmio_access(), which passes them to the symbolic hardware
 * plugins.
 *
 * se_mmu_resolve() sends the accesses to RAM pages with TLB_SYMB_MMIO down
 * the device path, like the native build does for the pages it cannot access
 * directly. se_hw_ld_beN() and se_hw_st_leN() replace do_ld_mmio_beN() and
 * do_st_mmio_leN() on that path. They do the access and report it. The flags
 * of the page are known there, so the other accesses pay nothing for the
 * check.
 *
 * An access that crosses a page boundary is reported once per page that has
 * symbolic hardware, with the physical address and the size of the part in
 * that page. The two pages need not be contiguous in physical memory, and
 * the native device path splits such an access in the same way.
 */

static inline void se_mmu_route_hw_page(MMULookupPageData *p) {
    if (p->size && (p->flags & TLB_SYMB_MMIO)) {
        p->flags |= TLB_MMIO;
    }
}

static inline void se_mmu_resolve(CPUState *cpu, MMULookupLocals *l, MMUAccessType type, uintptr_t ra) {
    /* Code fetches are not reported. Accesses of 16 bytes to RAM pages are not
       reported either: do_ld16_mmio_beN() and do_st16_mmio_leN() have no
       replacement, and the native ones would concretize the symbolic bytes of
       a RAM page. A device page already has TLB_MMIO. Its accesses reach
       se_hw_ld_beN() and se_hw_st_leN() unless they are 16 bytes long and fit
       in the page, in which case the native 16-byte functions handle them. */
    if (type == MMU_INST_FETCH || memop_size(l->memop) > 8) {
        return;
    }

    se_mmu_route_hw_page(&l->page[0]);
    se_mmu_route_hw_page(&l->page[1]);
}

/*
 * Replaces do_ld_mmio_beN() in bitcode. A device page is read through the
 * native function. A RAM page is read here, so that KLEE returns its symbolic
 * bytes as they are. The symbolic hardware plugins may replace the bytes that
 * were read, and the guest gets the bytes they return. Code fetches from a
 * device page are not reported.
 *
 * @param ret_be the bytes are appended to it, most significant first
 * @param haddr the host address of the bytes, which mmu_lookup1() computed;
 *        only valid for a RAM page
 * @return ret_be with the size bytes of the access appended
 */
static uint64_t se_hw_ld_beN(CPUState *cpu, CPUTLBEntryFull *full, uint64_t ret_be, vaddr addr, int size, int mmu_idx,
                             MMUAccessType type, uintptr_t ra, const uint8_t *haddr) {
    if (full->slow_flags[type] & TLB_MMIO) {
        ret_be = do_ld_mmio_beN(cpu, full, ret_be, addr, size, mmu_idx, type, ra);
        if (type == MMU_INST_FETCH) {
            return ret_be;
        }
    } else {
        for (int i = 0; i < size; i++) {
            ret_be = (ret_be << 8) | haddr[i];
        }
    }

    /* The handler converts the bytes to the guest byte order that the plugins
       use, and only when a plugin takes the access. Doing it here would put
       the symbolic bytes of every other access through a byte swap and back. */
    return tcg_llvm_trace_mmio_access(full->phys_addr | (addr & ~TARGET_PAGE_MASK), ret_be, size, 0);
}

/*
 * Replaces do_st_mmio_leN() in bitcode. A device page is written through the
 * native function. A RAM page is written here, so that KLEE stores symbolic
 * bytes as they are and copies the object first if it is shared. A store to
 * a read-only RAM page (TLB_DISCARD_WRITE) leaves memory unchanged and is not
 * reported.
 *
 * @param val_le the bytes are taken from it, least significant first
 * @param haddr the host address of the bytes, which mmu_lookup1() computed;
 *        only valid for a RAM page
 * @return val_le shifted right by the size bytes of the access
 */
static uint64_t se_hw_st_leN(CPUState *cpu, CPUTLBEntryFull *full, uint64_t val_le, vaddr addr, int size, int mmu_idx,
                             uintptr_t ra, uint8_t *haddr) {
    uint64_t value_le = size == 8 ? val_le : val_le & ((1ull << (size * 8)) - 1);
    int flags = full->slow_flags[MMU_DATA_STORE];

    if (flags & TLB_MMIO) {
        val_le = do_st_mmio_leN(cpu, full, val_le, addr, size, mmu_idx, ra);
    } else if (flags & TLB_DISCARD_WRITE) {
        return size == 8 ? 0 : val_le >> (size * 8);
    } else {
        for (int i = 0; i < size; i++) {
            haddr[i] = val_le;
            val_le >>= 8;
        }
    }

    tcg_llvm_trace_mmio_access(full->phys_addr | (addr & ~TARGET_PAGE_MASK), value_le, size, 1);
    return val_le;
}

/* Every caller of do_ld_mmio_beN() and do_st_mmio_leN() in cputlb.c passes
   p->full and p->addr, where p is the MMULookupPageData of the page. The
   macros take the host address from the same p. In bitcode, it is the addend
   of the TLB entry, not se_addend, so KLEE resolves it to the object of the
   page in the current state. Computing it again from the TLB would cost
   another tcg_llvm_fork_and_concretize() call. */
#define do_ld_mmio_beN(cpu, full, ret_be, addr, size, mmu_idx, type, ra) \
    se_hw_ld_beN(cpu, full, ret_be, addr, size, mmu_idx, type, ra, (const uint8_t *) p->haddr)
#define do_st_mmio_leN(cpu, full, val_le, addr, size, mmu_idx, ra) \
    se_hw_st_leN(cpu, full, val_le, addr, size, mmu_idx, ra, (uint8_t *) p->haddr)

#else

/* Builds without multi-path symbolic execution have no symbolic data and no
   shared KLEE objects. */
#define se_mmu_resolve(cpu, l, type, ra) ((void) 0)

static inline bool se_ram_ld_beN(CPUState *cpu, CPUTLBEntryFull *full, uint64_t *ret_be, vaddr addr, int size,
                                 int mmu_idx) {
    return false;
}

static inline bool se_ram_st_leN(CPUState *cpu, CPUTLBEntryFull *full, uint64_t *val_le, vaddr addr, int size,
                                 int mmu_idx) {
    return false;
}

#endif

#if defined(SYMBEX_LLVM_LIB)
/*
 * KLEE executes a call by pushing a stack frame, and a local variable whose
 * address is taken, such as the MMULookupLocals of every access, by
 * allocating a memory object and mapping it in the address space of the
 * state. Inlining the access path into its entry points lets the compiler
 * keep these locals in registers and fold the work that depends on constants.
 * The attribute applies to every function that cputlb.c defines from here to
 * the end of cputlb-symbex-ldst.c.inc, which ends the region.
 */
#pragma clang attribute push(__attribute__((always_inline)), apply_to = function)
#endif
