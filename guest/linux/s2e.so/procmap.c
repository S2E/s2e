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
#include <sys/mman.h>

#include "modules.h"

static int procmap_read_entry(procmap_entry_t *entry, const char *line) {
    char path[128];
    char read, write, execute;
    int matches = sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %c%c%c%*c %x %*s %d %127[^\n]", &entry->base, &entry->limit,
                         &read, &write, &execute, &entry->offset, &entry->inode, path);
    if (matches != 8) {
        return -1;
    }

    entry->size = entry->limit - entry->base;

    entry->perms = 0;

    if (read == 'r') {
        entry->perms |= PROT_READ;
    }

    if (write == 'w') {
        entry->perms |= PROT_WRITE;
    }

    if (execute == 'x') {
        entry->perms |= PROT_EXEC;
    }

    entry->name = our_strdup(path);

    return 0;
}

//
// Returns each module listed in /proc/self/maps as an array of entries. The last entry is NULL.
//
// Each row in /proc/self/maps describes a region of contiguous virtual memory in a process's address space. An example
// of a /proc/self/maps listing is given below:
//
// address                    perms  offset    dev    inode    path
// 00400000-0040c000          r-xp   00000000  08:01  3671038  /bin/cat
// 0060b000-0060c000          r--p   0000b000  08:01  3671038  /bin/cat
// 0060c000-0060d000          rw-p   0000c000  08:01  3671038  /bin/cat
// 017d4000-017f5000          rw-p   00000000  00:00  0        [heap]
// 7f3c75827000-7f3c75aff000  r--p   00000000  08:01  2097928  /usr/lib/locale/locale-archive
// 7f3c75aff000-7f3c75cbf000  r-xp   00000000  08:01  2626418  /lib/x86_64-linux-gnu/libc-2.23.so
// 7f3c75cbf000-7f3c75ebf000  ---p   001c0000  08:01  2626418  /lib/x86_64-linux-gnu/libc-2.23.so
// 7f3c75ebf000-7f3c75ec3000  r--p   001c0000  08:01  2626418  /lib/x86_64-linux-gnu/libc-2.23.so
// 7f3c75ec3000-7f3c75ec5000  rw-p   001c4000  08:01  2626418  /lib/x86_64-linux-gnu/libc-2.23.so
//
// Where:
//   address - start and end address of the memory region in the process's address space
//   perms   - read write execute private/shared permissions
//   offset  - file offset from where the memory region was mapped
//   dev     - major:minor device identifier
//   inode   - file number
//   path    - file path
//
// The inode field is used to uniquely identify modules in the map. Only non-zero inode values are considered. The
// inode value is checked while iterating over each row in the map. While this inode value remains the same, the
// `limit` address of the current `procmap_entry_t` is set to the maximum end address. When the inode changes, a new
// `procmap_entry_t` is added to the module map.
//
// This assumes that the different memory regions of a module are contiguous in memory. As we can see in the above
// example, this is not necessarily true - the executable region of /bin/cat ends at 0x40c000, while the next section
// (read-only data) starts at 0x60b000. However, this is a good enough approximation for now.
//
// https://stackoverflow.com/questions/33756119/relationship-between-vma-and-elf-segments
//
static int procmap_read(procmap_entry_t **entries, unsigned *count) {
    int ret = -1;
    char line[256];
    procmap_entry_t *tmp_entries = NULL;

    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        goto err;
    }

    *count = 0;

    procmap_entry_t *prev_entry = NULL;

    while (fgets(line, sizeof(line), fp)) {
        procmap_entry_t entry;
        if (procmap_read_entry(&entry, line) < 0) {
            continue;
        }

        if (entry.perms == 0) {
            free(entry.name);
            continue;
        }

        // The dynamic linker makes read-only certain portions of sections,
        // which creates multiple entries per section. This is because of RELRO protection.
        // So we need to merge the entries back together so that we can match
        // them with the original binary.
        if (prev_entry) {
            int contiguous = prev_entry->base + prev_entry->size == entry.base;
            int same_module = !strcmp(prev_entry->name, entry.name);
            int exec = (prev_entry->perms | entry.perms) & PROT_EXEC;
            if (contiguous && same_module && !exec) {
                prev_entry->perms |= entry.perms;
                prev_entry->size += entry.size;
                prev_entry->limit += entry.size;
                free(entry.name);
                continue;
            }
        }

        ++*count;
        procmap_entry_t *tmp = realloc(tmp_entries, *count * sizeof(*tmp));
        if (!tmp) {
            free(entry.name);
            goto err;
        }

        tmp[*count - 1] = entry;
        tmp_entries = tmp;
        prev_entry = &tmp[*count - 1];
    }

    ret = 0;
    *entries = tmp_entries;
err:
    if (fp) {
        fclose(fp);
    }

    if (ret) {
        free(tmp_entries);
    }

    return ret;
}

static void procmap_free_internal(procmap_entry_t *entries, unsigned count) {
    for (unsigned i = 0; i < count; ++i) {
        free(entries[i].name);
    }
    free(entries);
}

void procmap_free(procmap_entries_t *entries) {
    if (!entries) {
        return;
    }
    procmap_free_internal(entries->entries, entries->count);
    free(entries);
}

procmap_entries_t *procmap_get(void) {
    procmap_entries_t entries, *ret;
    if (procmap_read(&entries.entries, &entries.count) < 0) {
        return NULL;
    }

    ret = malloc(sizeof(*ret));
    if (!ret) {
        procmap_free_internal(entries.entries, entries.count);
        return NULL;
    }

    *ret = entries;
    return ret;
}

void procmap_dump(const procmap_entries_t *procmap) {
    procmap_entry_t *map = procmap->entries;

    s2e_printf("Process map:\n");
    for (unsigned i = 0; i < procmap->count; ++i) {
        s2e_printf("Base=%#" PRIxPTR " Limit=%#" PRIxPTR " Offset=%#010x Perms=%#02x Name=%s\n", map[i].base,
                   map[i].limit, map[i].offset, map[i].perms, map[i].name);
    }
}
