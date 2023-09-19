/*
 * Tiny Code Generator for QEMU
 *
 * Copyright (c) 2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef TCG_MEMOP
#define TCG_MEMOP

/* Constants for qemu_ld and qemu_st for the Memory Operation field.  */
typedef enum MemOp {
    MO_8 = 0,
    MO_16 = 1,
    MO_32 = 2,
    MO_64 = 3,
    MO_SIZE = 3, /* Mask for the above.  */

    MO_SIGN = 4, /* Sign-extended, otherwise zero-extended.  */

    MO_BSWAP = 8, /* Host reverse endian.  */
#ifdef HOST_WORDS_BIGENDIAN
    MO_LE = MO_BSWAP,
    MO_BE = 0,
#else
    MO_LE = 0,
    MO_BE = MO_BSWAP,
#endif
#ifdef TARGET_WORDS_BIGENDIAN
    MO_TE = MO_BE,
#else
    MO_TE = MO_LE,
#endif

    /* MO_UNALN accesses are never checked for alignment.
     * MO_ALIGN accesses will result in a call to the CPU's
     * do_unaligned_access hook if the guest address is not aligned.
     * The default depends on whether the target CPU defines ALIGNED_ONLY.
     *
     * Some architectures (e.g. ARMv8) need the address which is aligned
     * to a size more than the size of the memory access.
     * Some architectures (e.g. SPARCv9) need an address which is aligned,
     * but less strictly than the natural alignment.
     *
     * MO_ALIGN supposes the alignment size is the size of a memory access.
     *
     * There are three options:
     * - unaligned access permitted (MO_UNALN).
     * - an alignment to the size of an access (MO_ALIGN);
     * - an alignment to a specified size, which may be more or less than
     *   the access size (MO_ALIGN_x where 'x' is a size in bytes);
     */
    MO_ASHIFT = 4,
    MO_AMASK = 7 << MO_ASHIFT,
#ifdef ALIGNED_ONLY
    MO_ALIGN = 0,
    MO_UNALN = MO_AMASK,
#else
    MO_ALIGN = MO_AMASK,
    MO_UNALN = 0,
#endif
    MO_ALIGN_2 = 1 << MO_ASHIFT,
    MO_ALIGN_4 = 2 << MO_ASHIFT,
    MO_ALIGN_8 = 3 << MO_ASHIFT,
    MO_ALIGN_16 = 4 << MO_ASHIFT,
    MO_ALIGN_32 = 5 << MO_ASHIFT,
    MO_ALIGN_64 = 6 << MO_ASHIFT,

    /* Combinations of the above, for ease of use.  */
    MO_UB = MO_8,
    MO_UW = MO_16,
    MO_UL = MO_32,
    MO_UQ = MO_64,
    MO_SB = MO_SIGN | MO_8,
    MO_SW = MO_SIGN | MO_16,
    MO_SL = MO_SIGN | MO_32,
    MO_SQ = MO_SIGN | MO_64,
    MO_Q = MO_64,

    MO_LEUW = MO_LE | MO_UW,
    MO_LEUL = MO_LE | MO_UL,
    MO_LEUQ = MO_LE | MO_UQ,
    MO_LESW = MO_LE | MO_SW,
    MO_LESL = MO_LE | MO_SL,
    MO_LEQ = MO_LE | MO_Q,

    MO_BEUW = MO_BE | MO_UW,
    MO_BEUL = MO_BE | MO_UL,
    MO_BEUQ = MO_BE | MO_UQ,
    MO_BESW = MO_BE | MO_SW,
    MO_BESL = MO_BE | MO_SL,
    MO_BEQ = MO_BE | MO_Q,

    MO_TEUW = MO_TE | MO_UW,
    MO_TEUL = MO_TE | MO_UL,
    MO_TEUQ = MO_TE | MO_UQ,
    MO_TESW = MO_TE | MO_SW,
    MO_TESL = MO_TE | MO_SL,
    MO_TESQ = MO_TE | MO_SQ,
    MO_TEQ = MO_TE | MO_Q,

    MO_SSIZE = MO_SIZE | MO_SIGN,
} MemOp;

static inline unsigned memop_size(MemOp op) {
    return 1 << (op & MO_SIZE);
}

#endif