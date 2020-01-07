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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <s2e/monitors/linux.h>
#include "modules.h"

static void s2e_load_module(procmap_module_t *module, const char *current_process_path) {
    if (!strcmp(module->path, current_process_path)) {
        s2e_printf("Skipping %s, because it was already notified by the kernel\n", module->path);
        return;
    }

    struct S2E_LINUXMON_COMMAND_MODULE_LOAD load;
    struct S2E_LINUXMON_PHDR_DESC *phdr;
    size_t phdr_size = module->elf->loadable_phdr_num * sizeof(*phdr);

    phdr = malloc(phdr_size);
    if (!phdr) {
        s2e_printf("Could not allocate memory for command\n");
        return;
    }

    load.entry_point = module_get_runtime_entry_point(module);
    load.module_path = (uintptr_t) module->path;
    load.phdr = (uintptr_t) phdr;
    load.phdr_size = phdr_size;

    int i = 0;

    for (list_entry_t *entry = module->sections.next;
         (entry != &module->sections) && (i < module->elf->loadable_phdr_num); entry = entry->next, ++i) {
        const procmap_entry_t *section = CONTAINING_RECORD(entry, procmap_entry_t, entry);
        const procmap_elf_phdr_t *lphdr = &module->elf->loadable_phdr[i];

        phdr[i].index = lphdr->index;
        phdr[i].vma = section->base;
        phdr[i].p_type = lphdr->p_type;
        phdr[i].p_offset = lphdr->p_offset;
        phdr[i].p_vaddr = lphdr->p_vaddr;
        phdr[i].p_paddr = lphdr->p_paddr;
        phdr[i].p_filesz = lphdr->p_filesz;
        phdr[i].p_memsz = lphdr->p_memsz;
        phdr[i].p_flags = lphdr->p_flags;
        phdr[i].p_align = lphdr->p_align;

        phdr[i].mmap.address = section->base;
        phdr[i].mmap.size = section->size;
        phdr[i].mmap.prot = section->perms;
        phdr[i].mmap.flag = 0;
        phdr[i].mmap.pgoff = section->offset;
    }

    s2e_linux_load_module(getpid(), &load);

    free(phdr);
}

static void s2e_load_modules(const procmap_modules_t *modules) {
    char current_process_path[1024] = {0};

    if (readlink("/proc/self/exe", current_process_path, sizeof(current_process_path) - 1) < 0) {
        s2e_printf("Could not read current process path\n");
    }

    for (list_entry_t *entry = modules->head.next; entry != &modules->head; entry = entry->next) {
        procmap_module_t *module = CONTAINING_RECORD(entry, procmap_module_t, entry);
        s2e_load_module(module, current_process_path);
    }
}

void s2e_load_modules_from_procmap(void) {
    procmap_entries_t *proc_map = NULL;
    procmap_modules_t *modules = NULL;

    proc_map = procmap_get();
    if (!proc_map) {
        s2e_printf("Could not read proc map\n");
        return;
    }

    procmap_dump(proc_map);

    modules = modules_load_from_procmap(proc_map);
    if (!modules) {
        goto err;
    }

    modules_dump(modules);

    s2e_load_modules(modules);

err:
    modules_free(modules);
    procmap_free(proc_map);
}
