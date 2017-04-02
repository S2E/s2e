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

#include <cpu/config.h>
#include <sys/mman.h>
#include <sys/types.h>

#include <tcg/tcg.h>
#include "cpu.h"
#include "osdep.h"
#include "qemu-common.h"

#include "exec-tb.h"
#include "exec.h"

extern uint8_t *code_gen_buffer;

/* define log items */
typedef struct CPULogItem {
    int mask;
    const char *name;
    const char *help;
} CPULogItem;

/* log support */
#ifdef WIN32
static const char *logfilename = "qemu.log";
#else
static const char *logfilename = "/tmp/qemu.log";
#endif
FILE *logfile;
int loglevel;
static int log_append = 0;

const CPULogItem cpu_log_items[] = {
    {CPU_LOG_TB_OUT_ASM, "out_asm", "show generated host assembly code for each compiled TB"},
    {CPU_LOG_TB_IN_ASM, "in_asm", "show target assembly code for each compiled TB"},
    {CPU_LOG_TB_OP, "op", "show micro ops for each compiled TB"},
    {CPU_LOG_TB_OP_OPT, "op_opt", "show micro ops "
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
#ifdef CONFIG_LLVM
    {CPU_LOG_LLVM_IR, "llvm_ir", "show generated LLVM IR code"},
    {CPU_LOG_LLVM_ASM, "llvm_asm", "show LLVM-generated assembly code"},
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

void dump_exec_info(FILE *f, fprintf_function cpu_fprintf) {
    int i, target_code_size, max_target_code_size;
    int direct_jmp_count, direct_jmp2_count, cross_page;
    TranslationBlock *tb;

    target_code_size = 0;
    max_target_code_size = 0;
    cross_page = 0;
    direct_jmp_count = 0;
    direct_jmp2_count = 0;
    for (i = 0; i < g_nb_tbs; i++) {
        tb = &g_tbs[i];
        target_code_size += tb->size;
        if (tb->size > max_target_code_size)
            max_target_code_size = tb->size;
        if (tb->page_addr[1] != -1)
            cross_page++;
        if (tb->tb_next_offset[0] != 0xffff) {
            direct_jmp_count++;
            if (tb->tb_next_offset[1] != 0xffff) {
                direct_jmp2_count++;
            }
        }
    }
    /* XXX: avoid using doubles ? */
    cpu_fprintf(f, "Translation buffer state:\n");
    cpu_fprintf(f, "gen code size       %td/%ld\n", g_code_gen_ptr - code_gen_buffer, g_code_gen_buffer_max_size);
    cpu_fprintf(f, "TB count            %d/%d\n", g_nb_tbs, code_gen_max_blocks);
    cpu_fprintf(f, "TB avg target size  %d max=%d bytes\n", g_nb_tbs ? target_code_size / g_nb_tbs : 0,
                max_target_code_size);
    cpu_fprintf(f, "TB avg host size    %td bytes (expansion ratio: %0.1f)\n",
                g_nb_tbs ? (g_code_gen_ptr - code_gen_buffer) / g_nb_tbs : 0,
                target_code_size ? (double) (g_code_gen_ptr - code_gen_buffer) / target_code_size : 0);
    cpu_fprintf(f, "cross page TB count %d (%d%%)\n", cross_page, g_nb_tbs ? (cross_page * 100) / g_nb_tbs : 0);
    cpu_fprintf(f, "direct jump count   %d (%d%%) (2 jumps=%d %d%%)\n", direct_jmp_count,
                g_nb_tbs ? (direct_jmp_count * 100) / g_nb_tbs : 0, direct_jmp2_count,
                g_nb_tbs ? (direct_jmp2_count * 100) / g_nb_tbs : 0);
    cpu_fprintf(f, "\nStatistics:\n");
    cpu_fprintf(f, "TB flush count      %d\n", g_tb_flush_count);
    cpu_fprintf(f, "TB invalidate count %d\n", g_tb_phys_invalidate_count);
    cpu_fprintf(f, "TLB flush count     %d\n", g_tlb_flush_count);
    tcg_dump_info(f, cpu_fprintf);
}

/* enable or disable low levels log */
void cpu_set_log(int log_flags) {
    loglevel = log_flags;
    if (loglevel && !logfile) {
        logfile = fopen(logfilename, log_append ? "a" : "w");
        if (!logfile) {
            perror(logfilename);
            _exit(1);
        }
#if !defined(CONFIG_SOFTMMU)
        /* must avoid mmap() usage of glibc by setting a buffer "by hand" */
        {
            static char logfile_buf[4096];
            setvbuf(logfile, logfile_buf, _IOLBF, sizeof(logfile_buf));
        }
#elif defined(_WIN32)
        /* Win32 doesn't support line-buffering, so use unbuffered output. */
        setvbuf(logfile, NULL, _IONBF, 0);
#else
        setvbuf(logfile, NULL, _IOLBF, 0);
#endif
        log_append = 1;
    }
    if (!loglevel && logfile) {
        fclose(logfile);
        logfile = NULL;
    }
}

void cpu_set_log_filename(const char *filename) {
    logfilename = strdup(filename);
    if (logfile) {
        fclose(logfile);
        logfile = NULL;
    }
    cpu_set_log(loglevel);
}
