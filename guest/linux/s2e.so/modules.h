/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2019 Cyberhaven
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

#ifndef __S2E_MODULE_H__

#define __S2E_MODULE_H__

// #define s2e_printf printf

#include <inttypes.h>
#include <s2e/s2e.h>
#include "list.h"

typedef struct _procmap_elf_phdr_t {
    uint64_t index;
    uint64_t p_type;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_flags;
    uint64_t p_align;
} procmap_elf_phdr_t;

typedef struct procmap_elf_t {
    uint64_t entry_point;
    unsigned entry_point_idx;
    unsigned loadable_phdr_num;
    procmap_elf_phdr_t loadable_phdr[];
} procmap_elf_t;

typedef struct _procmap_entry_t {
    uintptr_t base;
    uintptr_t limit;
    uintptr_t size;
    unsigned perms;
    uint32_t offset;
    uint32_t inode;
    char *name;

    procmap_elf_phdr_t hdr;

    struct list_entry_t entry;
} procmap_entry_t;

typedef struct _procmap_entries_t {
    unsigned count;
    procmap_entry_t *entries;
} procmap_entries_t;

typedef struct _procmap_module_t {
    char *path;
    procmap_elf_t *elf;

    list_entry_t sections;
    list_entry_t entry;
} procmap_module_t;

typedef struct _procmap_modules_t {
    list_entry_t head;
} procmap_modules_t;

procmap_elf_t *elf_get_data(const char *path);

procmap_module_t *module_init(const char *path);
void module_free(procmap_module_t *module);
void module_dump(const procmap_module_t *module);
uint64_t module_get_runtime_entry_point(procmap_module_t *module);

procmap_modules_t *modules_init(void);
procmap_module_t *modules_find(const procmap_modules_t *modules, const char *module_path);
void modules_dump(const procmap_modules_t *modules);
procmap_modules_t *modules_load_from_procmap(const procmap_entries_t *procmap);
void modules_load(void);
void modules_add(procmap_modules_t *modules, procmap_module_t *module);
void modules_free(procmap_modules_t *modules);

procmap_entries_t *procmap_get(void);
void procmap_dump(const procmap_entries_t *procmap);
void procmap_free(procmap_entries_t *entries);

void s2e_load_modules_from_procmap(void);

// strdup is not a C99 function, so we have to provide it ourselves
char *our_strdup(const char *s);

#endif
