///
/// Copyright (C) 2014, Cyberhaven
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

#ifndef VMI_DECREE_H

#define VMI_DECREE_H

#include <inttypes.h>

namespace vmi {
namespace decree {

static const unsigned CI_NIDENT = 16;
struct DECREE32_hdr {
    uint8_t ci_mag0;    /* 0x7f */
    uint8_t ci_mag1;    /* 'C' */
    uint8_t ci_mag2;    /* 'G' */
    uint8_t ci_mag3;    /* 'C' */
    uint8_t ci_class;   /* 1 */
    uint8_t ci_data;    /* 1 */
    uint8_t ci_version; /* 1 */
    uint8_t ci_osabi;   /* 'C' */
    uint8_t ci_abivers; /* 1 */
    uint8_t ci_pad[7];
    uint16_t c_type;      /* Must be 2 for executable */
    uint16_t c_machine;   /* Must be 3 for i386 */
    uint32_t c_version;   /* Must be 1 */
    uint32_t c_entry;     /* Entry point */
    uint32_t c_phoff;     /* Program Header offset */
    uint32_t c_shoff;     /* Section Header offset */
    uint32_t c_flags;     /* Must be 0 */
    uint16_t c_ehsize;    /* DECREE header's size */
    uint16_t c_phentsize; /* Program header entry size */
    uint16_t c_phnum;     /* # program header entries */
    uint16_t c_shentsize; /* Section header entry size */
    uint16_t c_shnum;     /* # section header entries */
    uint16_t c_shstrndx;  /* sect header # of str table */
} __attribute__((packed));

/* The DECREE Executable Program Header */
struct DECREE32_phdr {
    uint32_t p_type;   /* Section type */
    uint32_t p_offset; /* Offset into the file */
    uint32_t p_vaddr;  /* Virtial program address */
    uint32_t p_paddr;  /* Set to zero */
    uint32_t p_filesz; /* Section bytes in the file */
    uint32_t p_memsz;  /* Section bytes in memory */
    uint32_t p_flags;  /* section flags */

    /* Acceptable flag combinations are:
     *      CPF_R
     *      CPF_R|CPF_W
     *      CPF_R|CPF_X
     *      CPF_R|CPF_W|CPF_X
     */

    uint32_t p_align; /* Bytes at which to align the
                       * section in memory.
                       * 0 or 1:      no alignment
                       * 4:           32bit alignment
                       * 4096:        page alignment
                       */
} __attribute__((packed));

static const unsigned PT_NULL = 0;                /* Unused header */
static const unsigned PT_LOAD = 1;                /* Segment is loaded into mem */
static const unsigned PT_PHDR = 6;                /* Program header tbl itself */
static const unsigned PT_DECREEPOV2 = 0x6ccccccc; /* CFE Type 2 PoV flag sect */

static const unsigned CPF_X = (1 << 0); /* Mapped executable */
static const unsigned CPF_W = (1 << 1); /* Mapped writeable */
static const unsigned CPF_R = (1 << 2); /* Mapped readable */
} // namespace decree
} // namespace vmi

#endif
