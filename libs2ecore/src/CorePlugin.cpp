///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2015, Cyberhaven
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

#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/s2e_libcpu.h>

#include <s2e/CorePlugin.h>

using namespace std;

namespace s2e {
S2E_DEFINE_PLUGIN(CorePlugin, "S2E core functionality", "Core", );
} // namespace s2e

extern "C" {
unsigned *g_s2e_before_memory_access_signals_count = nullptr;
unsigned *g_s2e_after_memory_access_signals_count = nullptr;
unsigned *g_s2e_on_translate_soft_interrupt_signals_count = nullptr;
unsigned *g_s2e_on_translate_block_start_signals_count = nullptr;
unsigned *g_s2e_on_translate_block_end_signals_count = nullptr;
unsigned *g_s2e_on_translate_block_complete_signals_count = nullptr;
unsigned *g_s2e_on_translate_instruction_start_signals_count = nullptr;
unsigned *g_s2e_on_translate_special_instruction_end_signals_count = nullptr;
unsigned *g_s2e_on_translate_jump_start_signals_count = nullptr;
unsigned *g_s2e_on_translate_lea_rip_relative_signals_count = nullptr;
unsigned *g_s2e_on_translate_instruction_end_signals_count = nullptr;
unsigned *g_s2e_on_translate_register_access_signals_count = nullptr;
unsigned *g_s2e_on_exception_signals_count = nullptr;
unsigned *g_s2e_on_page_fault_signals_count = nullptr;
unsigned *g_s2e_on_tlb_miss_signals_count = nullptr;
unsigned *g_s2e_on_port_access_signals_count = nullptr;
unsigned *g_s2e_on_privilege_change_signals_count = nullptr;
unsigned *g_s2e_on_page_directory_change_signals_count = nullptr;
unsigned *g_s2e_on_call_return_signals_count = nullptr;
}

using namespace s2e;

void CorePlugin::initialize() {
    g_s2e_before_memory_access_signals_count = onBeforeSymbolicDataMemoryAccess.getActiveSignalsPtr();
    g_s2e_after_memory_access_signals_count = onConcreteDataMemoryAccess.getActiveSignalsPtr();

    g_s2e_on_translate_soft_interrupt_signals_count = onTranslateSoftInterruptStart.getActiveSignalsPtr();
    g_s2e_on_translate_block_start_signals_count = onTranslateBlockStart.getActiveSignalsPtr();
    g_s2e_on_translate_block_end_signals_count = onTranslateBlockEnd.getActiveSignalsPtr();
    g_s2e_on_translate_block_complete_signals_count = onTranslateBlockComplete.getActiveSignalsPtr();
    g_s2e_on_translate_instruction_start_signals_count = onTranslateInstructionStart.getActiveSignalsPtr();
    g_s2e_on_translate_special_instruction_end_signals_count = onTranslateSpecialInstructionEnd.getActiveSignalsPtr();
    g_s2e_on_translate_jump_start_signals_count = onTranslateJumpStart.getActiveSignalsPtr();
    g_s2e_on_translate_lea_rip_relative_signals_count = onTranslateLeaRipRelative.getActiveSignalsPtr();
    g_s2e_on_translate_instruction_end_signals_count = onTranslateInstructionEnd.getActiveSignalsPtr();
    g_s2e_on_translate_register_access_signals_count = onTranslateRegisterAccessEnd.getActiveSignalsPtr();
    g_s2e_on_exception_signals_count = onException.getActiveSignalsPtr();
    g_s2e_on_tlb_miss_signals_count = onTlbMiss.getActiveSignalsPtr();
    g_s2e_on_page_fault_signals_count = onPageFault.getActiveSignalsPtr();
    g_s2e_on_port_access_signals_count = onPortAccess.getActiveSignalsPtr();
    g_s2e_on_privilege_change_signals_count = onPrivilegeChange.getActiveSignalsPtr();
    g_s2e_on_page_directory_change_signals_count = onPageDirectoryChange.getActiveSignalsPtr();
    g_s2e_on_call_return_signals_count = onCallReturnTranslate.getActiveSignalsPtr();

    onInitializationComplete.connect(sigc::mem_fun(*this, &CorePlugin::onInitializationCompleteCb));
}

void CorePlugin::onInitializationCompleteCb(S2EExecutionState *state) {
    S2EExecutor *exec = s2e()->getExecutor();

    unsigned *vars[] = {g_s2e_before_memory_access_signals_count,
                        g_s2e_after_memory_access_signals_count,
                        g_s2e_on_translate_block_start_signals_count,
                        g_s2e_on_translate_block_end_signals_count,
                        g_s2e_on_translate_instruction_start_signals_count,
                        g_s2e_on_translate_special_instruction_end_signals_count,
                        g_s2e_on_translate_jump_start_signals_count,
                        g_s2e_on_translate_lea_rip_relative_signals_count,
                        g_s2e_on_translate_instruction_end_signals_count,
                        g_s2e_on_translate_register_access_signals_count,
                        g_s2e_on_exception_signals_count,
                        g_s2e_on_page_fault_signals_count,
                        g_s2e_on_tlb_miss_signals_count,
                        g_s2e_on_port_access_signals_count,
                        g_s2e_on_privilege_change_signals_count,
                        g_s2e_on_page_directory_change_signals_count,
                        g_s2e_on_call_return_signals_count};

    for (unsigned i = 0; i < sizeof(vars) / sizeof(vars[0]); ++i) {
        exec->registerSharedExternalObject(state, vars[i], sizeof(*vars[i]));
    }

    exec->registerSharedExternalObject(state, &g_sqi, sizeof(g_sqi));
    exec->registerSharedExternalObject(state, &g_s2e_concretize_io_addresses, sizeof(g_s2e_concretize_io_addresses));
    exec->registerSharedExternalObject(state, &g_s2e_concretize_io_writes, sizeof(g_s2e_concretize_io_writes));
    exec->registerSharedExternalObject(state, &g_s2e_fork_on_symbolic_address, sizeof(g_s2e_fork_on_symbolic_address));
    exec->registerSharedExternalObject(state, &g_s2e_enable_mmio_checks, sizeof(g_s2e_enable_mmio_checks));
}
