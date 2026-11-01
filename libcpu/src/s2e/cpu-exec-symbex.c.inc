/// Copyright (C) 2026  Vitaly Chipounov
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

/// @file
/// The S2E parts of the CPU loop in accel/cpu-exec.c, which includes this file at
/// its end.

#ifdef CONFIG_SYMBEX
static bool s_tb_flush_requested;

/// Requests a flush of all TBs before the next TB lookup. Unlike tb_flush(), this
/// can be called while a TB runs.
void se_tb_safe_flush(void) {
    s_tb_flush_requested = true;
}
#endif

static void se_tb_flush_if_requested(CPUState *cpu) {
#ifdef CONFIG_SYMBEX
    if (unlikely(s_tb_flush_requested)) {
        s_tb_flush_requested = false;
        tb_flush(cpu);
    }
#endif
}

/// Flushes all TBs. This must not be called while a TB runs, because the flush makes
/// the code buffer of that TB available for new translations.
void tb_flush(CPUState *cpu) {
    tb_flush__exclusive_or_serial();
}

/// @return true when KLEE needs an LLVM function that this TB does not have.
static bool se_tb_lacks_llvm_function(CPUState *cpu, const TranslationBlock *tb) {
#if defined(CONFIG_SYMBEX_MP)
    return cpu->generate_llvm && !tb->llvm_function;
#else
    return false;
#endif
}

/// The interrupt window is closed during an interrupt shadow and opens after the
/// next instruction.
///
/// @return true once, when the window that the KVM client asked for has opened.
static bool se_interrupt_window_opened(CPUState *cpu) {
    CPUArchState *env = cpu_env(cpu);

    if (env->kvm_request_interrupt_window && (env->mflags & IF_MASK) && !(env->hflags & HF_INHIBIT_IRQ_MASK)) {
        env->kvm_request_interrupt_window = 0;
        return true;
    }
    return false;
}

static void dump_regs(CPUX86State *env, int isStart) {
#if defined(CONFIG_SYMBEX)
    target_ulong eax, ebx, ecx, edx, esi, edi, ebp, esp;
    g_sqi.regs.read_concrete(offsetof(CPUX86State, regs[R_EAX]), (uint8_t *) &eax, sizeof(eax));
    g_sqi.regs.read_concrete(offsetof(CPUX86State, regs[R_EBX]), (uint8_t *) &ebx, sizeof(ebx));
    g_sqi.regs.read_concrete(offsetof(CPUX86State, regs[R_ECX]), (uint8_t *) &ecx, sizeof(ecx));
    g_sqi.regs.read_concrete(offsetof(CPUX86State, regs[R_EDX]), (uint8_t *) &edx, sizeof(edx));
    g_sqi.regs.read_concrete(offsetof(CPUX86State, regs[R_ESI]), (uint8_t *) &esi, sizeof(esi));
    g_sqi.regs.read_concrete(offsetof(CPUX86State, regs[R_EDI]), (uint8_t *) &edi, sizeof(edi));
    g_sqi.regs.read_concrete(offsetof(CPUX86State, regs[R_EBP]), (uint8_t *) &ebp, sizeof(ebp));
    g_sqi.regs.read_concrete(offsetof(CPUX86State, regs[R_ESP]), (uint8_t *) &esp, sizeof(esp));

    fprintf(logfile, "%c cs:eip=%lx:%lx eax=%lx ebx=%lx ecx=%lx edx=%lx esi=%lx edi=%lx ebp=%lx ss:esp=%lx:%lx\n",
            isStart ? 's' : 'e', (uint64_t) env->segs[R_CS].selector, (uint64_t) env->eip, (uint64_t) eax,
            (uint64_t) ebx, (uint64_t) ecx, (uint64_t) edx, (uint64_t) esi, (uint64_t) edi, (uint64_t) ebp,
            (uint64_t) env->segs[R_SS].selector, (uint64_t) esp);
#else
    fprintf(logfile, "%c cs:eip=%lx:%lx eax=%lx ebx=%lx ecx=%lx edx=%lx esi=%lx edi=%lx ebp=%lx ss:esp=%lx:%lx\n",
            isStart ? 's' : 'e', (uint64_t) env->segs[R_CS].selector, (uint64_t) env->eip, (uint64_t) env->regs[R_EAX],
            (uint64_t) env->regs[R_EBX], (uint64_t) env->regs[R_ECX], (uint64_t) env->regs[R_EDX],
            (uint64_t) env->regs[R_ESI], (uint64_t) env->regs[R_EDI], (uint64_t) env->regs[R_EBP],
            (uint64_t) env->segs[R_SS].selector, (uint64_t) env->regs[R_ESP]);
#endif
}

/// Runs a TB natively or in KLEE.
///
/// @return the value of tcg_qemu_tb_exec() for a TB that ran natively, and 0 for
/// a TB that KLEE ran or declined. A declined TB did not run. The next lookup uses
/// its cflags, because the loop has already consumed cflags_next_tb, so that a request
/// for a one-instruction TB survives the regeneration of the TB with an LLVM function.
static uintptr_t se_tb_exec(CPUState *cpu, TranslationBlock *tb) {
    CPUArchState *env = cpu_env(cpu);
    uintptr_t last_tb;

    libcpu_log_mask(CPU_LOG_EXEC, "se_tb_exec cs:eip=%#lx:%#lx e=%#lx fl=%lx riw=%d\n",
                    (uint64_t) env->segs[R_CS].selector, (uint64_t) env->eip, (uint64_t) env->eip + tb->size,
                    (uint64_t) env->mflags, env->kvm_request_interrupt_window);

    if (libcpu_log_enabled() && libcpu_loglevel_mask(CPU_LOG_EXEC)) {
        dump_regs(env, 1);
    }

#if defined(CONFIG_SYMBEX)
    cpu->se_tb_abort = 0;
    cpu->se_current_tb = tb;
    if (likely(*g_sqi.mode.fast_concrete_invocation)) {
        **g_sqi.mode.running_exception_emulation_code = 0;
        last_tb = tcg_qemu_tb_exec(env, tb->tc.ptr);
    } else {
        last_tb = g_sqi.exec.tb_exec(env, tb);
    }
    cpu->se_current_tb = NULL;

    if (last_tb == SE_TB_EXEC_DECLINED) {
        cpu->cflags_next_tb = tb->cflags;
        last_tb = 0;
    }
#else
    last_tb = tcg_qemu_tb_exec(env, tb->tc.ptr);
#endif

    if (libcpu_log_enabled() && libcpu_loglevel_mask(CPU_LOG_EXEC)) {
        dump_regs(env, 0);
    }

    return last_tb;
}
