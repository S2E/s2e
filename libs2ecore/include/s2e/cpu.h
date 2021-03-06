///
/// Copyright (C) 2016, Cyberhaven
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
///

///
/// This header gathers all libcpu/libtcg includes.
/// It must be used instead of manually including their headers
/// in every source file.
///

// Order of include files is important, dont let clang-format
// mess with it until we fix it.
// clang-format off

#ifndef __S2E_CPU_H__

#define __S2E_CPU_H__
#include "s2e_config.h"
#ifdef __cplusplus
extern "C" {
#endif
#if defined(TARGET_I386) || defined(TARGET_X86_64)
#include <cpu/i386/cpu.h>
#include <cpu/i386/helper.h>
#elif defined(TARGET_ARM)
#include <cpu/arm/cpu.h>
#include <cpu/arm/helper.h>
#else
#error Unsupported target architecture
#endif

#include <cpu/exec.h>
#include <cpu/cpu-common.h>
#include <libcpu-compiler.h>
#include <cpu/se_libcpu.h>
#include <cpu/tlb.h>
#if defined(TARGET_I386) || defined(TARGET_X86_64)
#include <cpu/apic.h>
#endif
#include <cpu/ioport.h>
#include <cpu/cpus.h>
#include <cpu/disas.h>

#include <timer.h>
#include <tcg/tcg.h>


// TODO: move kvm apis to the right headers
void s2e_kvm_flush_disk(void);
void s2e_kvm_save_device_state(void);
void s2e_kvm_restore_device_state(void);
void s2e_kvm_sync_sregs(void);
void s2e_kvm_clone_process(void);
void s2e_kvm_cpu_exit_request(void);

// Called by the kvm interface
// TODO: make these function pointers for better decoupling?
int s2e_dev_save(const void *buffer, size_t size);
int s2e_dev_restore(void *buffer, int pos, size_t size);

#define fast_setjmp setjmp
#define fast_longjmp longjmp
#define fast_jmp_buf jmp_buf


extern CPUArchState *env;
void raise_exception(CPUArchState *env, int exception_index);
void raise_exception_err(CPUArchState *env, int exception_index,
                         int error_code);
void raise_exception_err_ra(CPUArchState *env, int exception_index,
                            int error_code, uintptr_t retaddr);

#if defined(TARGET_I386) || defined(TARGET_X86_64)
extern const uint8_t parity_table[256];
extern const uint8_t rclw_table[32];
extern const uint8_t rclb_table[32];
#endif

#if defined(TARGET_I386) || defined(TARGET_X86_64)
void se_do_interrupt_all(int intno, int is_int, int error_code,
                             target_ulong next_eip, int is_hw);
uint64_t helper_set_cc_op_eflags(void);
#elif defined(TARGET_ARM)
void se_do_interrupt_arm(void);
void se_set_armv7m_external_irq(int irq_num);
void se_enable_all_armv7m_external_irq(int serial);
void se_enable_systick_irq(int mode);
uint32_t se_get_active_armv7m_external_irq(int serial);
#else
#error Unsupported target architecture
#endif

#if defined(TARGET_I386) || defined(TARGET_X86_64)
void s2e_gen_pc_update(void *context, target_ulong pc, target_ulong cs_base);
#elif defined(TARGET_ARM)
void s2e_gen_pc_update(void *context, target_ulong pc);
#else
#error Unsupported target architecture
#endif

void s2e_gen_flags_update(void *context);

#ifdef __cplusplus
}
#endif

#endif
