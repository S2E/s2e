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
/// between the lookup and the access.
///
/// The file also replaces the atomic load and store primitives of
/// ldst_atomicity.c.inc in builds with symbolic execution.

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

#else

/* KLEE handles symbolic data and copies shared objects itself, and the other
   builds have neither. */
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
