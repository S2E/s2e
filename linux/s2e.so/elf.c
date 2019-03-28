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

#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>

#include "modules.h"

static char *read_file_data(const char *name, size_t *size_) {
    char *ret = NULL;
    FILE *fp = fopen(name, "rb");
    if (!fp) {
        goto err;
    }

    if (fseek(fp, 0, SEEK_END) < 0) {
        goto err;
    }

    ssize_t size = ftell(fp);
    if (size < 0) {
        goto err;
    }

    if (fseek(fp, 0, SEEK_SET) < 0) {
        goto err;
    }

    ret = malloc(size);
    if (!ret) {
        goto err;
    }

    if (fread(ret, size, 1, fp) != 1) {
        s2e_printf("Could not read %zd bytes from %s\n", size, name);
        goto err;
    }

    *size_ = size;

    fclose(fp);
    return ret;

err:
    if (fp) {
        fclose(fp);
    }

    free(ret);

    return NULL;
}

procmap_elf_t *elf_get_data(const char *name) {
    procmap_elf_t *ret = NULL;
    Elf *elf = NULL;
    Elf32_Ehdr *hdr = NULL;
    size_t phdr_num = 0, loadable_section_count = 0;
    int bits = 0;
    size_t size = 0;
    char *data = NULL;

    if (elf_version(EV_CURRENT) == EV_NONE) {
        goto err;
    }

    data = read_file_data(name, &size);
    if (!data) {
        goto err;
    }

    elf = elf_memory(data, size);
    if (!elf) {
        goto err;
    }

    if (elf_kind(elf) != ELF_K_ELF) {
        goto err;
    }

    hdr = (Elf32_Ehdr *) data;
    if (hdr->e_ident[EI_CLASS] == ELFCLASS64) {
        bits = 64;
    } else if (hdr->e_ident[EI_CLASS] == ELFCLASS32) {
        bits = 32;
    } else {
        goto err;
    }

    if (elf_getphdrnum(elf, &phdr_num)) {
        goto err;
    }

    ret = malloc(sizeof(*ret) + sizeof(procmap_elf_phdr_t) * phdr_num);
    if (!ret) {
        goto err;
    }

    ret->entry_point_idx = 0;

    for (unsigned i = 0; i < phdr_num; ++i) {
        procmap_elf_phdr_t phdr_copy;
        phdr_copy.index = i;

        if (bits == 32) {
            Elf32_Ehdr *ehdr = elf32_getehdr(elf);
            ret->entry_point = ehdr->e_entry;

            Elf32_Phdr *phdr = elf32_getphdr(elf);
            phdr_copy.p_type = phdr[i].p_type;
            phdr_copy.p_offset = phdr[i].p_offset;
            phdr_copy.p_vaddr = phdr[i].p_vaddr;
            phdr_copy.p_paddr = phdr[i].p_paddr;
            phdr_copy.p_filesz = phdr[i].p_filesz;
            phdr_copy.p_memsz = phdr[i].p_memsz;
            phdr_copy.p_flags = phdr[i].p_flags;
            phdr_copy.p_align = phdr[i].p_align;

        } else {
            Elf64_Ehdr *ehdr = elf64_getehdr(elf);
            ret->entry_point = ehdr->e_entry;

            Elf64_Phdr *phdr = elf64_getphdr(elf);
            phdr_copy.p_type = phdr[i].p_type;
            phdr_copy.p_offset = phdr[i].p_offset;
            phdr_copy.p_vaddr = phdr[i].p_vaddr;
            phdr_copy.p_paddr = phdr[i].p_paddr;
            phdr_copy.p_filesz = phdr[i].p_filesz;
            phdr_copy.p_memsz = phdr[i].p_memsz;
            phdr_copy.p_flags = phdr[i].p_flags;
            phdr_copy.p_align = phdr[i].p_align;
        }

        if (phdr_copy.p_type == PT_LOAD) {
            ret->loadable_phdr[loadable_section_count] = phdr_copy;
            if (ret->entry_point >= phdr_copy.p_vaddr && ret->entry_point < phdr_copy.p_vaddr + phdr_copy.p_memsz) {
                ret->entry_point_idx = loadable_section_count;
            }
            loadable_section_count++;
        }
    }

    ret->loadable_phdr_num = loadable_section_count;

err:
    if (elf) {
        elf_end(elf);
    }

    free(data);
    return ret;
}
