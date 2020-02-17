///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
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

extern "C" {
// clang-format off
#include <cpu/i386/cpu.h>
#include <tcg/tcg-op.h>

#include <cpu/exec.h>

#include <timer.h>
#include <qdict.h>

#define s2e_gen_pc_update instr_gen_pc_update
#define s2e_gen_flags_update instr_gen_flags_update

// clang-format on
extern struct CPUX86State *env;
void s2e_gen_pc_update(void *context, target_ulong pc, target_ulong cs_base);
void s2e_gen_flags_update(void *context);
}

#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>

#include <s2e/s2e_libcpu.h>
#include <s2e/s2e_config.h>

#include <s2e/CorePlugin.h>
#include <klee/Common.h>

using namespace s2e;

/********************************/
/* Functions called from libcpu */

extern "C" {

int g_s2e_enable_signals = true;

void s2e_tcg_execution_handler(void *signal, uint64_t pc) {
    try {
        ExecutionSignal *s = (ExecutionSignal *) signal;
        if (g_s2e_enable_signals) {
            s->emit(g_s2e_state, pc);
        }
    } catch (s2e::CpuExitException &) {
        longjmp(env->jmp_env, 1);
    }
}

void s2e_tcg_custom_instruction_handler(uint64_t arg) {
    assert(!g_s2e->getCorePlugin()->onCustomInstruction.empty() &&
           "You must activate a plugin that uses custom instructions.");

    try {
        g_s2e->getCorePlugin()->onCustomInstruction.emit(g_s2e_state, arg);
    } catch (s2e::CpuExitException &) {
        longjmp(env->jmp_env, 1);
    }
}

void s2e_tcg_emit_custom_instruction(uint64_t arg) {
    TCGv_i64 t0 = tcg_const_i64(arg);

    TCGTemp *args[1] = {tcgv_i64_temp(t0)};
    tcg_gen_callN((void *) s2e_tcg_custom_instruction_handler, nullptr, 1, args);

    tcg_temp_free_i64(t0);
}

/* Instrument generated code to emit signal on execution */
/* Next pc, when != -1, indicates with which value to update the program counter
   before calling the annotation. This is useful when instrumenting instructions
   that do not explicitely update the program counter by themselves. */
static void s2e_tcg_instrument_code(ExecutionSignal *signal, uint64_t pc, uint64_t nextpc = -1) {
    if (nextpc != (uint64_t) -1) {
#if TCG_TARGET_REG_BITS == 64 && defined(TARGET_X86_64)
        TCGv_i64 tpc = tcg_const_i64((tcg_target_ulong) nextpc);
        tcg_gen_st_i64(tpc, cpu_env, offsetof(CPUX86State, eip));
        tcg_temp_free_i64(tpc);
#else
        TCGv_i32 tpc = tcg_const_i32((tcg_target_ulong) nextpc);
        tcg_gen_st_i32(tpc, cpu_env, offsetof(CPUX86State, eip));
        tcg_temp_free_i32(tpc);
#endif
    }

    TCGv_ptr t0 = tcg_const_local_ptr(signal);
    TCGv_i64 t1 = tcg_const_i64(pc);
    TCGTemp *args[2] = {tcgv_ptr_temp(t0), tcgv_i64_temp(t1)};

    tcg_gen_callN((void *) s2e_tcg_execution_handler, nullptr, 2, args);

    tcg_temp_free_i64(t1);
    tcg_temp_free_ptr(t0);
}

void s2e_on_translate_soft_interrupt_start(void *context, TranslationBlock *tb, uint64_t pc, unsigned vector) {
    assert(g_s2e_state->isActive());

    S2ETranslationBlock *se_tb = static_cast<S2ETranslationBlock *>(tb->se_tb);
    ExecutionSignal *signal = static_cast<ExecutionSignal *>(se_tb->executionSignals.back());
    assert(signal->empty());

    try {
        g_s2e->getCorePlugin()->onTranslateSoftInterruptStart.emit(signal, g_s2e_state, tb, pc, vector);
        if (!signal->empty()) {
            s2e_gen_pc_update(context, pc, tb->cs_base);
            s2e_tcg_instrument_code(signal, pc - tb->cs_base);
            se_tb->executionSignals.push_back(new ExecutionSignal);
        }
    } catch (s2e::CpuExitException &) {
        longjmp(env->jmp_env, 1);
    }
}

void s2e_on_translate_block_start(void *context, TranslationBlock *tb, uint64_t pc) {
    assert(g_s2e_state->isActive());

    S2ETranslationBlock *se_tb = static_cast<S2ETranslationBlock *>(tb->se_tb);
    ExecutionSignal *signal = static_cast<ExecutionSignal *>(se_tb->executionSignals.back());
    assert(signal->empty());

    try {
        g_s2e->getCorePlugin()->onTranslateBlockStart.emit(signal, g_s2e_state, tb, pc);
        if (!signal->empty()) {
            s2e_gen_pc_update(context, pc, tb->cs_base);
            s2e_tcg_instrument_code(signal, pc - tb->cs_base);
            se_tb->executionSignals.push_back(new ExecutionSignal);
        }
    } catch (s2e::CpuExitException &) {
        longjmp(env->jmp_env, 1);
    }
}

void s2e_on_translate_block_end(TranslationBlock *tb, uint64_t insPc, int staticTarget, uint64_t targetPc) {
    assert(g_s2e_state->isActive());

    S2ETranslationBlock *se_tb = static_cast<S2ETranslationBlock *>(tb->se_tb);
    ExecutionSignal *signal = static_cast<ExecutionSignal *>(se_tb->executionSignals.back());
    assert(signal->empty());

    try {
        g_s2e->getCorePlugin()->onTranslateBlockEnd.emit(signal, g_s2e_state, tb, insPc, staticTarget, targetPc);
    } catch (s2e::CpuExitException &) {
        longjmp(env->jmp_env, 1);
    }

    if (!signal->empty()) {
        s2e_tcg_instrument_code(signal, insPc - tb->cs_base);
        se_tb->executionSignals.push_back(new ExecutionSignal);
    }
}

void s2e_on_translate_block_complete(TranslationBlock *tb, uint64_t pc) {
    assert(g_s2e_state->isActive());

    try {
        g_s2e->getCorePlugin()->onTranslateBlockComplete.emit(g_s2e_state, tb, pc);
    } catch (s2e::CpuExitException &) {
        longjmp(env->jmp_env, 1);
    }
}

void s2e_on_translate_instruction_start(void *context, TranslationBlock *tb, uint64_t pc) {
    assert(g_s2e_state->isActive());

    S2ETranslationBlock *se_tb = static_cast<S2ETranslationBlock *>(tb->se_tb);
    ExecutionSignal *signal = static_cast<ExecutionSignal *>(se_tb->executionSignals.back());
    assert(signal->empty());

    try {
        g_s2e->getCorePlugin()->onTranslateInstructionStart.emit(signal, g_s2e_state, tb, pc);
        if (!signal->empty()) {
            s2e_gen_pc_update(context, pc, tb->cs_base);
            s2e_tcg_instrument_code(signal, pc - tb->cs_base);
            se_tb->executionSignals.push_back(new ExecutionSignal);
        }
    } catch (s2e::CpuExitException &) {
        longjmp(env->jmp_env, 1);
    }
}

void s2e_on_translate_special_instruction_end(void *context, TranslationBlock *tb, uint64_t pc,
                                              enum special_instruction_t type, int update_pc) {
    assert(g_s2e_state->isActive());

    S2ETranslationBlock *se_tb = static_cast<S2ETranslationBlock *>(tb->se_tb);
    ExecutionSignal *signal = static_cast<ExecutionSignal *>(se_tb->executionSignals.back());
    assert(signal->empty());

    try {
        g_s2e->getCorePlugin()->onTranslateSpecialInstructionEnd.emit(signal, g_s2e_state, tb, pc, type);
        if (!signal->empty()) {

            if (update_pc) {
                s2e_gen_pc_update(context, pc, tb->cs_base);
            }

            s2e_tcg_instrument_code(signal, pc - tb->cs_base);
            se_tb->executionSignals.push_back(new ExecutionSignal);
        }
    } catch (s2e::CpuExitException &) {
        longjmp(env->jmp_env, 1);
    }
}

void s2e_on_translate_jump_start(void *context, TranslationBlock *tb, uint64_t pc, int jump_type) {
    assert(g_s2e_state->isActive());

    S2ETranslationBlock *se_tb = static_cast<S2ETranslationBlock *>(tb->se_tb);
    ExecutionSignal *signal = static_cast<ExecutionSignal *>(se_tb->executionSignals.back());
    assert(signal->empty());

    try {
        g_s2e->getCorePlugin()->onTranslateJumpStart.emit(signal, g_s2e_state, tb, pc, jump_type);
        if (!signal->empty()) {
            s2e_gen_pc_update(context, pc, tb->cs_base);
            s2e_tcg_instrument_code(signal, pc - tb->cs_base);
            se_tb->executionSignals.push_back(new ExecutionSignal);
        }
    } catch (s2e::CpuExitException &) {
        longjmp(env->jmp_env, 1);
    }
}

void s2e_on_translate_indirect_cti_start(void *context, TranslationBlock *tb, uint64_t pc, int rm, int op, int offset) {
    assert(g_s2e_state->isActive());

    S2ETranslationBlock *se_tb = static_cast<S2ETranslationBlock *>(tb->se_tb);
    ExecutionSignal *signal = static_cast<ExecutionSignal *>(se_tb->executionSignals.back());
    assert(signal->empty());

    try {
        g_s2e->getCorePlugin()->onTranslateICTIStart.emit(signal, g_s2e_state, tb, pc, rm, op, offset);
        if (!signal->empty()) {
            s2e_gen_pc_update(context, pc, tb->cs_base);
            s2e_tcg_instrument_code(signal, pc - tb->cs_base);
            se_tb->executionSignals.push_back(new ExecutionSignal);
        }
    } catch (s2e::CpuExitException &) {
        longjmp(env->jmp_env, 1);
    }
}

void s2e_on_translate_lea_rip_relative(void *context, TranslationBlock *tb, uint64_t pc, uint64_t addr) {
    assert(g_s2e_state->isActive());

    S2ETranslationBlock *se_tb = static_cast<S2ETranslationBlock *>(tb->se_tb);
    ExecutionSignal *signal = static_cast<ExecutionSignal *>(se_tb->executionSignals.back());

    assert(signal->empty());
    try {
        g_s2e->getCorePlugin()->onTranslateLeaRipRelative.emit(signal, g_s2e_state, tb, pc, addr);

        if (!signal->empty()) {
            s2e_gen_pc_update(context, pc, tb->cs_base);
            s2e_tcg_instrument_code(signal, pc - tb->cs_base);
            se_tb->executionSignals.push_back(new ExecutionSignal);
        }
    } catch (s2e::CpuExitException &) {
        longjmp(env->jmp_env, 1);
    }
}

// Nextpc is the program counter of the instruction that
// follows the one at pc, only if it does not change the control flow.
void s2e_on_translate_instruction_end(void *context, TranslationBlock *tb, uint64_t pc, uint64_t nextpc) {
    assert(g_s2e_state->isActive());

    S2ETranslationBlock *se_tb = static_cast<S2ETranslationBlock *>(tb->se_tb);
    ExecutionSignal *signal = static_cast<ExecutionSignal *>(se_tb->executionSignals.back());
    assert(signal->empty());

    try {
        g_s2e->getCorePlugin()->onTranslateInstructionEnd.emit(signal, g_s2e_state, tb, pc);
        if (!signal->empty()) {
            s2e_gen_flags_update(context);
            s2e_tcg_instrument_code(signal, pc, nextpc);
            se_tb->executionSignals.push_back(new ExecutionSignal);
        }
    } catch (s2e::CpuExitException &) {
        longjmp(env->jmp_env, 1);
    }
}

void s2e_on_translate_register_access(TranslationBlock *tb, uint64_t pc, uint64_t readMask, uint64_t writeMask,
                                      int isMemoryAccess) {
    assert(g_s2e_state->isActive());

    S2ETranslationBlock *se_tb = static_cast<S2ETranslationBlock *>(tb->se_tb);
    ExecutionSignal *signal = static_cast<ExecutionSignal *>(se_tb->executionSignals.back());
    assert(signal->empty());

    try {
        g_s2e->getCorePlugin()->onTranslateRegisterAccessEnd.emit(signal, g_s2e_state, tb, pc, readMask, writeMask,
                                                                  (bool) isMemoryAccess);

        if (!signal->empty()) {
            s2e_tcg_instrument_code(signal, pc - tb->cs_base);
            se_tb->executionSignals.push_back(new ExecutionSignal);
        }
    } catch (s2e::CpuExitException &) {
        longjmp(env->jmp_env, 1);
    }
}

void s2e_on_exception(unsigned intNb) {
    assert(g_s2e_state->isActive());

    try {
        g_s2e->getCorePlugin()->onException.emit(g_s2e_state, intNb, g_s2e_state->regs()->getPc());
    } catch (s2e::CpuExitException &) {
        longjmp(env->jmp_env, 1);
    }
}

static CPUTimer *s_timer = nullptr;

static void s2e_timer_cb(void *opaque) {
    CorePlugin *c = (CorePlugin *) opaque;
    g_s2e->getExecutor()->updateStats(g_s2e_state);
    c->onTimer.emit();
    libcpu_mod_timer(s_timer, libcpu_get_clock_ms(rt_clock) + 1000);
}

void s2e_init_timers() {
    g_s2e->getDebugStream() << "Initializing periodic timer" << '\n';
    /* Initialize the timer handler */
    void *cp = g_s2e->getPlugin("CorePlugin");
    assert(cp);
    s_timer = libcpu_new_timer_ms(rt_clock, s2e_timer_cb, cp);
    libcpu_mod_timer(s_timer, libcpu_get_clock_ms(rt_clock) + 1000);
}

// XXX: precise exceptions here
// The location may be imprecise if called from a helper
//(retaddr will be set to null there)
void s2e_after_memory_access(uint64_t vaddr, uint64_t value, unsigned size, unsigned flags, uintptr_t retaddr) {
    if (retaddr && env->se_current_tb) {
        cpu_restore_state(env, (uintptr_t) retaddr);
        flags |= MEM_TRACE_FLAG_PRECISE;
    }

    try {
        g_s2e->getCorePlugin()->onConcreteDataMemoryAccess.emit(g_s2e_state, vaddr, value, size, flags);
    } catch (s2e::CpuExitException &) {
        longjmp(env->jmp_env, 1);
    }
}

uint8_t __ldb_mmu_trace(uint8_t *host_addr, target_ulong vaddr) {
    s2e_after_memory_access(vaddr, *host_addr, 1, 0, (uintptr_t) GETPC());
    return *host_addr;
}

uint16_t __ldw_mmu_trace(uint16_t *host_addr, target_ulong vaddr) {
    s2e_after_memory_access(vaddr, *host_addr, 2, 0, (uintptr_t) GETPC());
    return *host_addr;
}

uint32_t __ldl_mmu_trace(uint32_t *host_addr, target_ulong vaddr) {
    s2e_after_memory_access(vaddr, *host_addr, 4, 0, (uintptr_t) GETPC());
    return *host_addr;
}

uint64_t __ldq_mmu_trace(uint64_t *host_addr, target_ulong vaddr) {
    s2e_after_memory_access(vaddr, *host_addr, 8, 0, (uintptr_t) GETPC());
    return *host_addr;
}

void __stb_mmu_trace(uint8_t *host_addr, target_ulong vaddr) {
    s2e_after_memory_access(vaddr, *host_addr, 1, MEM_TRACE_FLAG_WRITE, (uintptr_t) GETPC());
}

void __stw_mmu_trace(uint16_t *host_addr, target_ulong vaddr) {
    s2e_after_memory_access(vaddr, *host_addr, 2, MEM_TRACE_FLAG_WRITE, (uintptr_t) GETPC());
}

void __stl_mmu_trace(uint32_t *host_addr, target_ulong vaddr) {
    s2e_after_memory_access(vaddr, *host_addr, 4, MEM_TRACE_FLAG_WRITE, (uintptr_t) GETPC());
}

void __stq_mmu_trace(uint64_t *host_addr, target_ulong vaddr) {
    s2e_after_memory_access(vaddr, *host_addr, 8, MEM_TRACE_FLAG_WRITE, (uintptr_t) GETPC());
}

void s2e_on_page_fault(uint64_t addr, int is_write, void *retaddr) {
    if (retaddr && env->se_current_tb) {
        cpu_restore_state(env, (uintptr_t) retaddr);
    }

    try {
        g_s2e->getCorePlugin()->onPageFault.emit(g_s2e_state, addr, (bool) is_write);
    } catch (s2e::CpuExitException &) {
        longjmp(env->jmp_env, 1);
    }
}

void s2e_on_tlb_miss(uint64_t addr, int is_write, void *retaddr) {
    if (retaddr && env->se_current_tb) {
        cpu_restore_state(env, (uintptr_t) retaddr);
    }

    try {
        g_s2e->getCorePlugin()->onTlbMiss.emit(g_s2e_state, addr, (bool) is_write);
    } catch (s2e::CpuExitException &) {
        longjmp(env->jmp_env, 1);
    }
}

void s2e_trace_port_access(uint64_t port, uint64_t value, unsigned size, int isWrite, void *retaddr) {
    if (g_s2e->getCorePlugin()->onPortAccess.empty()) {
        return;
    }

    if (retaddr) {
        cpu_restore_state(env, (uintptr_t) retaddr);
    }

    try {
        g_s2e->getCorePlugin()->onPortAccess.emit(g_s2e_state, klee::ConstantExpr::create(port, 64),
                                                  klee::ConstantExpr::create(value, size), isWrite);
    } catch (s2e::CpuExitException &) {
        longjmp(env->jmp_env, 1);
    }
}

void s2e_on_privilege_change(unsigned previous, unsigned current) {
    assert(g_s2e_state->isActive());

    try {
        g_s2e->getCorePlugin()->onPrivilegeChange.emit(g_s2e_state, previous, current);
    } catch (s2e::CpuExitException &) {
        pabort("Cannot throw exceptions here. VM state may be inconsistent at this point.");
    }
}

void s2e_on_page_directory_change(uint64_t previous, uint64_t current) {
    assert(g_s2e_state->isActive());

    try {
        g_s2e->getCorePlugin()->onPageDirectoryChange.emit(g_s2e_state, previous, current);
    } catch (s2e::CpuExitException &) {
        pabort("Cannot throw exceptions here. VM state may be inconsistent at this point.");
    }
}

void s2e_on_initialization_complete(void) {
    try {
        g_s2e->getCorePlugin()->onInitializationComplete.emit(g_s2e_state);
    } catch (s2e::CpuExitException &) {
        pabort("Cannot throw exceptions here. VM state may be inconsistent at this point.");
    }
}

int s2e_on_call_return_translate(uint64_t pc, int isCall) {
    bool instrument = false;
    try {
        g_s2e->getCorePlugin()->onCallReturnTranslate.emit(g_s2e_state, pc, isCall, &instrument);
    } catch (s2e::CpuExitException &) {
        pabort("Cannot throw exceptions here.");
    }
    return instrument;
}
}
