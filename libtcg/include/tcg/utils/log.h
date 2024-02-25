/// Copyright (C) 2003  Fabrice Bellard
/// Copyright (C) 2016-2019  Cyberhaven
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

#ifndef TCG_LOG_H

#define TCG_LOG_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The deprecated global variables: */
extern FILE *logfile;
extern int loglevel;

typedef int (*fprintf_function)(FILE *f, const char *fmt, ...);

#define CPU_LOG_TB_OUT_ASM (1 << 0)
#define CPU_LOG_TB_IN_ASM  (1 << 1)
#define CPU_LOG_TB_OP      (1 << 2)
#define CPU_LOG_TB_OP_OPT  (1 << 3)
#define CPU_LOG_INT        (1 << 4)
#define CPU_LOG_EXEC       (1 << 5)
#define CPU_LOG_PCALL      (1 << 6)
#define CPU_LOG_IOPORT     (1 << 7)
#define CPU_LOG_TB_CPU     (1 << 8)
#define CPU_LOG_RESET      (1 << 9)
#define CPU_LOG_LLVM_IR    (1 << 10)
#define CPU_LOG_LLVM_ASM   (1 << 11)

/* Log settings checking macros: */

/* Returns true if libcpu_log() will really write somewhere
 */
#define libcpu_log_enabled() (logfile != NULL)

/* Returns true if a bit is set in the current loglevel mask
 */
#define libcpu_loglevel_mask(b) ((loglevel & (b)) != 0)

/* Logging functions: */

/* main logging function
 */
#define libcpu_log(...)                      \
    do {                                     \
        if (logfile)                         \
            fprintf(logfile, ##__VA_ARGS__); \
    } while (0)

/* vfprintf-like logging function
 */
#define libcpu_log_vprintf(fmt, va)     \
    do {                                \
        if (logfile)                    \
            vfprintf(logfile, fmt, va); \
    } while (0)

/* log only if a bit is set on the current loglevel mask
 */
#define libcpu_log_mask(b, ...)              \
    do {                                     \
        if (loglevel & (b))                  \
            fprintf(logfile, ##__VA_ARGS__); \
    } while (0)

/* Special cases: */

/* cpu_dump_state() logging functions: */
#define log_cpu_state(env, f) cpu_dump_state((env), logfile, fprintf, (f));
#define log_cpu_state_mask(b, env, f)  \
    do {                               \
        if (loglevel & (b))            \
            log_cpu_state((env), (f)); \
    } while (0)

#define log_target_disas(env, start, len, flags) target_disas(env, logfile, (start), (len), (flags))
#define log_host_disas(start, len)               host_disas(logfile, (start), (len))

/* page_dump() output to the log file: */
#define log_page_dump() page_dump(logfile)

/* Maintenance: */

/* fflush() the log file */
#define libcpu_log_flush() fflush(logfile)

/* Close the log file */
#define libcpu_log_close() \
    do {                   \
        fclose(logfile);   \
        logfile = NULL;    \
    } while (0)

/* Set up a new log file */
#define libcpu_log_set_file(f) \
    do {                       \
        logfile = (f);         \
    } while (0)

/* Set up a new log file, only if none is set */
#define libcpu_log_try_set_file(f) \
    do {                           \
        if (!logfile)              \
            logfile = (f);         \
    } while (0)

int cpu_str_to_log_mask(const char *str);

#ifdef __cplusplus
}
#endif

#endif
