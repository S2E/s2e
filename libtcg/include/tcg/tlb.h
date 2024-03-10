#ifndef TCG_TLB_H

#define TCG_TLB_H

#include <inttypes.h>
#include <tcg/utils/osdep.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_SYMBEX
#define CPU_TLB_ENTRY_BITS 6
#else
#define CPU_TLB_ENTRY_BITS 5
#endif

typedef struct CPUTLBEntry {
    /* bit TARGET_LONG_BITS to TARGET_PAGE_BITS : virtual address
       bit TARGET_PAGE_BITS-1..4  : Nonzero for accesses that should not
                                    go directly to ram.
       bit 3                      : indicates that the entry is invalid
       bit 2..0                   : zero
    */
    uint64_t addr_read;
    uint64_t addr_write;
    uint64_t addr_code;

    /* Addend to virtual address to get host address.  IO accesses
       use the corresponding iotlb value.  */
    uintptr_t addend;

#ifdef CONFIG_SYMBEX
    uintptr_t se_addend;
    void *objectState;

    /* padding to get a power of two size */
    uint8_t dummy[(1 << CPU_TLB_ENTRY_BITS) - (sizeof(uint64_t) * 3 + 3 * sizeof(uintptr_t))];
#else
    uint8_t dummy[(1 << CPU_TLB_ENTRY_BITS) - (sizeof(uint64_t) * 3 + 1 * sizeof(uintptr_t))];
#endif
} CPUTLBEntry;

QEMU_BUILD_BUG_ON(sizeof(CPUTLBEntry) != (1 << CPU_TLB_ENTRY_BITS));

/*
 * Data elements that are per MMU mode, accessed by the fast path.
 * The structure is aligned to aid loading the pair with one insn.
 */
typedef struct CPUTLBDescFast {
    /* Contains (n_entries - 1) << CPU_TLB_ENTRY_BITS */
    uintptr_t mask;
    /* The array of tlb entries itself. */
    CPUTLBEntry *table;
} CPUTLBDescFast QEMU_ALIGNED(2 * sizeof(void *));

/* Flags stored in the low bits of the TLB virtual address.  These are
 * defined so that fast path ram access is all zeros.
 * The flags all must be between TARGET_PAGE_BITS and
 * maximum address alignment bit.
 */
/* Zero if TLB entry is valid.  */
#define TLB_INVALID_MASK (1 << (TARGET_PAGE_BITS - 1))
/* Set if TLB entry references a clean RAM page.  The iotlb entry will
   contain the page physical address.  */
#define TLB_NOTDIRTY (1 << (TARGET_PAGE_BITS - 2))
/* Set if TLB entry is an IO callback.  */
#define TLB_MMIO (1 << (TARGET_PAGE_BITS - 3))
/* Set if TLB entry must have MMU lookup repeated for every access */
#define TLB_RECHECK (1 << (TARGET_PAGE_BITS - 4))

#ifdef CONFIG_SYMBEX
/* Set if TLB entry points to a page that has symbolic data */
#define TLB_SYMB (1 << (TARGET_PAGE_BITS - 5))

/* Set if TLB entry points to a page that does not belong to us (only for write) */
#define TLB_NOT_OURS (1 << (TARGET_PAGE_BITS - 6))

#endif

/* Indicates that accesses to the page must be traced */
#define TLB_MEM_TRACE (1 << (TARGET_PAGE_BITS - 7))

/* Use this mask to check interception with an alignment mask
 * in a TCG backend.
 */
#ifdef CONFIG_SYMBEX
#define TLB_FLAGS_MASK (TLB_INVALID_MASK | TLB_NOTDIRTY | TLB_MMIO | TLB_SYMB | TLB_RECHECK | TLB_NOT_OURS)
#else
#define TLB_FLAGS_MASK (TLB_INVALID_MASK | TLB_NOTDIRTY | TLB_MMIO | TLB_RECHECK)
#endif

#ifdef __cplusplus
}
#endif

#endif