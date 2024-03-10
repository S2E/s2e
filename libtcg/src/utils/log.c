/// Copyright (C) 2003  Fabrice Bellard
/// Copyright (C) 2010  Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016  Cyberhaven
/// Copyrights of all contributions belong to their respective owners.
///
/// This library is free software; you can redistribute it and/or
/// modify it under the terms of the GNU Library General Public
/// License as published by the Free Software Foundation; either
/// version 2 of the License, or (at your option) any later version.
///
/// This library is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
/// Library General Public License for more details.
///
/// You should have received a copy of the GNU Library General Public
/// License along with this library; if not, see <http://www.gnu.org/licenses/>.

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>

#include <tcg/utils/log.h>
#include <tcg/utils/osdep.h>

extern uint8_t *code_gen_buffer;

/* define log items */
typedef struct CPULogItem {
    int mask;
    const char *name;
    const char *help;
} CPULogItem;

/* log support */
FILE *logfile;
int loglevel;

const CPULogItem cpu_log_items[] = {
    {CPU_LOG_TB_OUT_ASM, "out_asm", "show generated host assembly code for each compiled TB"},
    {CPU_LOG_TB_IN_ASM, "in_asm", "show target assembly code for each compiled TB"},
    {CPU_LOG_TB_OP, "op", "show micro ops for each compiled TB"},
    {CPU_LOG_TB_OP_OPT, "op_opt",
     "show micro ops "
#ifdef TARGET_I386
     "before eflags optimization and "
#endif
     "after liveness analysis"},
    {CPU_LOG_INT, "int", "show interrupts/exceptions in short format"},
    {CPU_LOG_EXEC, "exec", "show trace before each executed TB (lots of logs)"},
    {CPU_LOG_TB_CPU, "cpu", "show CPU state before block translation"},
#ifdef TARGET_I386
    {CPU_LOG_PCALL, "pcall", "show protected mode far calls/returns/exceptions"},
    {CPU_LOG_RESET, "cpu_reset", "show CPU state before CPU resets"},
#endif
#ifdef DEBUG_IOPORT
    {CPU_LOG_IOPORT, "ioport", "show all i/o ports accesses"},
#endif
#ifdef CONFIG_SYMBEX
    {CPU_LOG_LLVM_IR, "llvm_ir", "show generated LLVM IR code"},
#endif
    {0, NULL, NULL},
};

static int cmp1(const char *s1, int n, const char *s2) {
    if (strlen(s2) != n)
        return 0;
    return memcmp(s1, s2, n) == 0;
}

/* takes a comma separated list of log masks. Return 0 if error. */
int cpu_str_to_log_mask(const char *str) {
    const CPULogItem *item;
    int mask;
    const char *p, *p1;

    p = str;
    mask = 0;
    for (;;) {
        p1 = strchr(p, ',');
        if (!p1)
            p1 = p + strlen(p);
        if (cmp1(p, p1 - p, "all")) {
            for (item = cpu_log_items; item->mask != 0; item++) {
                mask |= item->mask;
            }
        } else {
            for (item = cpu_log_items; item->mask != 0; item++) {
                if (cmp1(p, p1 - p, item->name))
                    goto found;
            }
            return 0;
        }
    found:
        mask |= item->mask;
        if (*p1 != ',')
            break;
        p = p1 + 1;
    }
    return mask;
}

extern int g_tlb_flush_count;
