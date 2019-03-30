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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "modules.h"

char *our_strdup(const char *str) {
    size_t len = strlen(str);
    char *ret = malloc(len + 1);
    if (!ret) {
        return ret;
    }
    strcpy(ret, str);
    return ret;
}

void module_dump(const procmap_module_t *module) {
    for (list_entry_t *entry = module->sections.next; entry != &module->sections; entry = entry->next) {
        procmap_entry_t *section = CONTAINING_RECORD(entry, procmap_entry_t, entry);

        s2e_printf("   Base=0x%08" PRIxPTR " Size=0x%08" PRIxPTR " Offset=0x%08x Perms=0x%02x Name=%s\n", section->base,
                   section->size, section->offset, section->perms, section->name);
    }
}

static void module_add_section(procmap_module_t *module, procmap_entry_t *entry) {
    list_add_tail(&module->sections, &entry->entry);
}

procmap_module_t *module_init(const char *path) {
    procmap_module_t *ret = malloc(sizeof(procmap_module_t));
    if (!ret) {
        goto err;
    }

    memset(ret, 0, sizeof(*ret));
    ret->path = our_strdup(path);
    if (!ret->path) {
        goto err;
    }

    ret->elf = elf_get_data(path);
    if (!ret->elf) {
        goto err;
    }

    // TODO: open the module and load its header
    list_init_head(&ret->sections);

    return ret;

err:
    if (ret) {
        free(ret->path);
    }
    free(ret);
    return NULL;
}

void module_free(procmap_module_t *module) {
    free(module->path);
    free(module->elf);
    free(module);
}

procmap_modules_t *modules_init(void) {
    procmap_modules_t *ret = malloc(sizeof(procmap_modules_t));
    if (!ret) {
        return NULL;
    }

    memset(ret, 0, sizeof(*ret));
    list_init_head(&ret->head);
    return ret;
}

procmap_module_t *modules_find(const procmap_modules_t *modules, const char *module_path) {
    for (list_entry_t *entry = modules->head.next; entry != &modules->head; entry = entry->next) {
        procmap_module_t *module = CONTAINING_RECORD(entry, procmap_module_t, entry);
        if (!strcmp(module_path, module->path)) {
            return module;
        }
    }
    return NULL;
}

void modules_dump(const procmap_modules_t *modules) {
    s2e_printf("Dumping modules\n");

    for (list_entry_t *entry = modules->head.next; entry != &modules->head; entry = entry->next) {
        procmap_module_t *module = CONTAINING_RECORD(entry, procmap_module_t, entry);
        s2e_printf("Module %s - entry_point=%#" PRIx64 " loadable_phdr_num=%d\n", module->path,
                   module->elf->entry_point, module->elf->loadable_phdr_num);
        module_dump(module);
    }
}

void modules_add(procmap_modules_t *modules, procmap_module_t *module) {
    list_add_tail(&modules->head, &module->entry);
}

void modules_free(procmap_modules_t *modules) {
    if (!modules) {
        return;
    }

    while (!list_empty(&modules->head)) {
        list_entry_t *entry = list_remove_tail(&modules->head);
        procmap_module_t *module = CONTAINING_RECORD(entry, procmap_module_t, entry);
        module_free(module);
    }

    free(modules);
}

procmap_modules_t *modules_load_from_procmap(const procmap_entries_t *proc_map) {
    procmap_modules_t *modules = modules_init();

    if (!modules) {
        return NULL;
    }

    for (unsigned i = 0; i < proc_map->count; ++i) {
        procmap_entry_t *pme = &proc_map->entries[i];
        procmap_module_t *module = modules_find(modules, pme->name);
        if (!module) {
            module = module_init(pme->name);
            if (!module) {
                s2e_printf("Could not load %s\n", pme->name);
                continue;
            }
            modules_add(modules, module);
        }

        module_add_section(module, pme);
    }

    return modules;
}

uint64_t module_get_runtime_entry_point(procmap_module_t *module) {
    unsigned i = 0;
    for (list_entry_t *entry = module->sections.next; entry != &module->sections; entry = entry->next, ++i) {
        if (i == module->elf->entry_point_idx) {
            procmap_entry_t *section = CONTAINING_RECORD(entry, procmap_entry_t, entry);
            uint64_t native = module->elf->loadable_phdr[module->elf->entry_point_idx].p_vaddr;
            return module->elf->entry_point - native + section->base;
        }
    }

    return 0;
}
