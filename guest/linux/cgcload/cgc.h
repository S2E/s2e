/*
 * linux/fs/binfmt_cgc.c
 * Copyright (c) 2014 Jason L. Wright (jason@thought.net)
 *
 * Functions/module to load binaries targetting the DARPA Cyber Grand Challenge.
 * CGCOS binaries most thoroughly resemble static ELF binaries, thus this
 * code is derived from:
 *
 * linux/fs/binfmt_elf.c
 *
 * These are the functions used to load ELF format executables as used
 * on SVr4 machines.  Information on the format may be found in the book
 * "UNIX SYSTEM V RELEASE 4 Programmers Guide: Ansi C and Programming Support
 * Tools".
 *
 * Copyright 1993, 1994: Eric Youngdale (ericy@cais.com).
 */

#ifndef __CGC_HDR__

#define __CGC_HDR__

#include <inttypes.h>

/* The CGC Executable File Header */
#define CI_NIDENT 16
typedef struct CGC32_hdr {
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
    uint16_t c_ehsize;    /* CGC header's size */
    uint16_t c_phentsize; /* Program header entry size */
    uint16_t c_phnum;     /* # program header entries */
    uint16_t c_shentsize; /* Section header entry size */
    uint16_t c_shnum;     /* # section header entries */
    uint16_t c_shstrndx;  /* sect header # of str table */
} CGC32_hdr;

/* The CGC Executable Program Header */
typedef struct CGC32_phdr {
    uint32_t p_type;          /* Section type */
#define PT_NULL    0          /* Unused header */
#define PT_LOAD    1          /* Segment is loaded into mem */
#define PT_PHDR    6          /* Program header tbl itself */
#define PT_CGCPOV2 0x6ccccccc /* CFE Type 2 PoV flag sect */
    uint32_t p_offset;        /* Offset into the file */
    uint32_t p_vaddr;         /* Virtial program address */
    uint32_t p_paddr;         /* Set to zero */
    uint32_t p_filesz;        /* Section bytes in the file */
    uint32_t p_memsz;         /* Section bytes in memory */
    uint32_t p_flags;         /* section flags */
#define CPF_X (1 << 0)        /* Mapped executable */
#define CPF_W (1 << 1)        /* Mapped writeable */
#define CPF_R (1 << 2)        /* Mapped readable */
    /* Acceptable flag combinations are:
     *	CPF_R
     *	CPF_R|CPF_W
     *	CPF_R|CPF_X
     *	CPF_R|CPF_W|CPF_X
     */

    uint32_t p_align; /* Bytes at which to align the
                       * section in memory.
                       * 0 or 1:	no alignment
                       * 4:		32bit alignment
                       * 4096:	page alignment
                       */
} CGC32_Phdr;

#endif