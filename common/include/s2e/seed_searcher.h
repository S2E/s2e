/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2016 Cyberhaven
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

#ifndef S2E_SEED_H
#define S2E_SEED_H

#include <s2e/s2e.h>
#include "seed_searcher/commands.h"

#ifdef __cplusplus
extern "C" {
#endif

static int s2e_seed_get_file(char *file, size_t bytes, int *should_fork) {
    struct S2E_SEEDSEARCHER_COMMAND cmd;
    memset(&cmd, 0, sizeof(cmd));

    cmd.Command = SEED_GET_SEED_FILE;
    cmd.GetFile.FileName = (uintptr_t) file;
    cmd.GetFile.FileNameSizeInBytes = bytes;
    cmd.GetFile.Result = 0;

    s2e_begin_atomic();
    s2e_disable_all_apic_interrupts();
    s2e_invoke_plugin("SeedSearcher", &cmd, sizeof(cmd));
    s2e_enable_all_apic_interrupts();
    s2e_end_atomic();

    int ret = 0;
    switch (cmd.GetFile.Result) {
        /* No seed file, other states exploring, no need to fork */
        case 0:
            ret = -1;
            *should_fork = 0;
            break;

        /* No seed file, start exploration without seeds */
        case 1:
            ret = -1;
            *should_fork = 1;
            break;

        /* Seed file available, start exploring it */
        case 2:
            ret = 0;
            *should_fork = 1;
            break;
    }

    return ret;
}

static void s2e_seed_searcher_enable(void) {
    struct S2E_SEEDSEARCHER_COMMAND cmd;
    memset(&cmd, 0, sizeof(cmd));

    cmd.Command = SEED_ENABLE_SEARCHER;

    s2e_begin_atomic();
    s2e_disable_all_apic_interrupts();
    s2e_invoke_plugin("SeedSearcher", &cmd, sizeof(cmd));
    s2e_enable_all_apic_interrupts();
    s2e_end_atomic();
}

#ifdef __cplusplus
}
#endif

#endif
