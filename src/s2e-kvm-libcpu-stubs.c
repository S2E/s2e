///
/// Copyright (C) 2015-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <assert.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cpu/apic.h>
#include <cpu/exec.h>
#include <tcg/tcg.h>
#include <timer.h>

#ifdef CONFIG_SYMBEX
#include <s2e/monitor.h>
#endif

#include "s2e-kvm-interface.h"

FILE *logfile;
int loglevel = 0;
int singlestep = 0;
int mem_prealloc = 0; /* force preallocation of physical target memory */
const char *mem_path = NULL;
ram_addr_t ram_size = 128 * 1024 * 1024;

void cpu_smm_update(CPUX86State *env) {
    assert(0 && "Not implemented");
}

/* TSC handling */
extern uint64_t g_clock_start;
extern uint64_t g_clock_offset;
uint64_t cpu_get_tsc(CPUX86State *env) {
    return cpu_get_real_ticks() - g_clock_offset + g_clock_start;
}

extern CPUX86State *env;

uint8_t cpu_get_apic_tpr(DeviceState *d) {
    return env->v_tpr;
}

void cpu_set_apic_tpr(DeviceState *d, uint8_t val) {
    env->v_tpr = val;
}

void cpu_set_apic_base(DeviceState *d, uint64_t val) {
    env->v_apic_base = val;
}

uint64_t cpu_get_apic_base(DeviceState *d) {
    return env->v_apic_base;
}

void cpu_set_ferr(CPUX86State *s) {
    assert(0 && "Not implemented");
}

int cpu_is_bsp(CPUX86State *env) {
    return env->cpu_index == 0;
}

void libcpu_system_reset_request(void) {
    assert(0 && "Not implemented");
}

void apic_sipi(DeviceState *d) {
    assert(0 && "Not implemented");
}

void apic_init_reset(DeviceState *d) {
    //    assert(0 && "Not implemented");
}

void apic_handle_tpr_access_report(DeviceState *d, target_ulong ip, TPRAccess access) {
    assert(0 && "Not implemented");
}

int cpu_get_pic_interrupt(CPUArchState *env) {
    int ret = env->kvm_irq;
#ifdef SE_KVM_DEBUG_IRQ
    printf("%s = %d\n", __FUNCTION__, ret);
#endif

    env->kvm_irq = -1;

    /**
     * Sometimes this is called when there is no interrupt pending,
     * so return -1.
     */
    return ret;
}

#ifdef CONFIG_SYMBEX
extern const char *g_s2e_shared_dir;
char *libcpu_find_file(int type, const char *name) {
    int len;
    const char *subdir;
    char *buf;
    const char *data_dir = g_s2e_shared_dir;

    /* If name contains path separators then try it as a straight path.  */
    if ((strchr(name, '/') || strchr(name, '\\')) && access(name, R_OK) == 0) {
        return g_strdup(name);
    }
    switch (type) {
        case FILE_TYPE_BIOS:
            subdir = "";
            break;
        case FILE_TYPE_KEYMAP:
            subdir = "keymaps/";
            break;
        default:
            abort();
    }
    len = strlen(data_dir) + strlen(name) + strlen(subdir) + 2;
    buf = g_malloc0(len);
    snprintf(buf, len, "%s/%s%s", data_dir, subdir, name);
    if (access(buf, R_OK)) {
        g_free(buf);
        return NULL;
    }
    return buf;
}
#endif
