///
/// Copyright (C) 2015-2017, Cyberhaven
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

// TODO: fix license

#include <cpu/se_libcpu.h>

#ifdef CONFIG_SYMBEX
#include <s2e/ExprInterface.h>
#include <s2e/s2e_libcpu.h>

extern "C" {
extern se_do_interrupt_all_t g_s2e_do_interrupt_all;
}
#endif

void init_s2e_libcpu_interface(struct se_libcpu_interface_t *sqi) {
#ifdef CONFIG_SYMBEX
    sqi->size = sizeof(*sqi);

    sqi->mode.fast_concrete_invocation = &g_s2e_fast_concrete_invocation;
    sqi->mode.fork_on_symbolic_address = &g_s2e_fork_on_symbolic_address;
    sqi->mode.running_exception_emulation_code = &g_s2e_running_exception_emulation_code;
    sqi->mode.single_path_mode = &g_s2e_single_path_mode;
    sqi->mode.allow_custom_instructions = &g_s2e_allow_custom_instructions;
    sqi->mode.concretize_io_writes = &g_s2e_concretize_io_writes;
    sqi->mode.concretize_io_addresses = &g_s2e_concretize_io_addresses;

    sqi->exec.helper_register_symbol = helper_register_symbol;
    sqi->exec.cleanup_tb_exec = s2e_libcpu_cleanup_tb_exec;
    sqi->exec.finalize_tb_exec = s2e_libcpu_finalize_tb_exec;
    sqi->exec.is_yielded = s2e_is_yielded;
    sqi->exec.is_runnable = s2e_is_runnable;
    sqi->exec.is_running_concrete = s2e_is_running_concrete;
    sqi->exec.reset_state_switch_timer = s2e_reset_state_switch_timer;
    sqi->exec.switch_to_symbolic = s2e_switch_to_symbolic;
    sqi->exec.tb_exec = se_libcpu_tb_exec;
    sqi->exec.do_interrupt_all = g_s2e_do_interrupt_all;

    sqi->tb.tb_alloc = se_tb_alloc;
    sqi->tb.flush_tb_cache = s2e_flush_tb_cache;
    sqi->tb.set_tb_function = s2e_set_tb_function;
    sqi->tb.is_tb_instrumented = s2e_is_tb_instrumented;

    sqi->tlb.flush_tlb_cache = s2e_flush_tlb_cache;
    sqi->tlb.flush_tlb_cache_page = se_flush_tlb_cache_page;
    sqi->tlb.update_tlb_entry = s2e_update_tlb_entry;

    sqi->regs.read_concrete = s2e_read_register_concrete;
    sqi->regs.write_concrete = s2e_write_register_concrete;
    sqi->regs.set_cc_op_eflags = s2e_set_cc_op_eflags;

    sqi->mem.read_dirty_mask = se_read_dirty_mask;
    sqi->mem.write_dirty_mask = se_write_dirty_mask;
    sqi->mem.dma_read = s2e_dma_read;
    sqi->mem.dma_write = s2e_dma_write;
    sqi->mem.read_ram_concrete = s2e_read_ram_concrete;
    sqi->mem.write_ram_concrete = s2e_write_ram_concrete;
    sqi->mem.read_ram_concrete_check = s2e_read_ram_concrete_check;
    sqi->mem.read_mem_io_vaddr = s2e_read_mem_io_vaddr;
    sqi->mem.is_port_symbolic = s2e_is_port_symbolic;
    sqi->mem.is_mmio_symbolic = s2e_is_mmio_symbolic;
    sqi->mem.is_vmem_symbolic = se_is_vmem_symbolic;
    sqi->mem.get_host_address = se_get_host_address;

    sqi->expr.mgr = s2e_expr_mgr;
    sqi->expr.clear = s2e_expr_clear;
    sqi->expr.mgr_clear = s2e_expr_mgr_clear;
    sqi->expr.andc = s2e_expr_and;
    sqi->expr.to_constant = s2e_expr_to_constant;
    sqi->expr.set = s2e_expr_set;
    sqi->expr.write_cpu = s2e_expr_write_cpu;
    sqi->expr.read_cpu = s2e_expr_read_cpu;
    sqi->expr.read_mem_l = s2e_expr_read_mem_l;
    sqi->expr.read_mem_q = s2e_expr_read_mem_q;

    sqi->events.before_memory_access_signals_count = g_s2e_before_memory_access_signals_count;
    sqi->events.after_memory_access_signals_count = g_s2e_after_memory_access_signals_count;
    sqi->events.on_translate_soft_interrupt_signals_count = g_s2e_on_translate_soft_interrupt_signals_count;
    sqi->events.on_translate_block_start_signals_count = g_s2e_on_translate_block_start_signals_count;
    sqi->events.on_translate_block_end_signals_count = g_s2e_on_translate_block_end_signals_count;
    sqi->events.on_translate_block_complete_signals_count = g_s2e_on_translate_block_complete_signals_count;
    sqi->events.on_translate_instruction_start_signals_count = g_s2e_on_translate_instruction_start_signals_count;
    sqi->events.on_translate_special_instruction_end_signals_count =
        g_s2e_on_translate_special_instruction_end_signals_count;
    sqi->events.on_translate_jump_start_signals_count = g_s2e_on_translate_jump_start_signals_count;
    sqi->events.on_translate_lea_rip_relative_signals_count = g_s2e_on_translate_lea_rip_relative_signals_count;
    sqi->events.on_translate_instruction_end_signals_count = g_s2e_on_translate_instruction_end_signals_count;
    sqi->events.on_translate_register_access_signals_count = g_s2e_on_translate_register_access_signals_count;
    sqi->events.on_exception_signals_count = g_s2e_on_exception_signals_count;
    sqi->events.on_page_fault_signals_count = g_s2e_on_page_fault_signals_count;
    sqi->events.on_tlb_miss_signals_count = g_s2e_on_tlb_miss_signals_count;
    sqi->events.on_port_access_signals_count = g_s2e_on_port_access_signals_count;
    sqi->events.on_privilege_change_signals_count = g_s2e_on_privilege_change_signals_count;
    sqi->events.on_page_directory_change_signals_count = g_s2e_on_page_directory_change_signals_count;
    sqi->events.on_call_return_signals_count = g_s2e_on_call_return_signals_count;

    sqi->events.on_privilege_change = s2e_on_privilege_change;
    sqi->events.on_page_directory_change = s2e_on_page_directory_change;
    sqi->events.on_page_fault = s2e_on_page_fault;
    sqi->events.on_tlb_miss = s2e_on_tlb_miss;
    sqi->events.after_memory_access = s2e_after_memory_access;
    sqi->events.trace_port_access = s2e_trace_port_access;
    sqi->events.tcg_execution_handler = helper_s2e_tcg_execution_handler;
    sqi->events.tcg_custom_instruction_handler = helper_s2e_tcg_custom_instruction_handler;
    sqi->events.tcg_emit_custom_instruction = s2e_tcg_emit_custom_instruction;

    sqi->events.on_translate_soft_interrupt_start = s2e_on_translate_soft_interrupt_start;
    sqi->events.on_translate_block_start = s2e_on_translate_block_start;
    sqi->events.on_translate_block_end = s2e_on_translate_block_end;
    sqi->events.on_translate_block_complete = s2e_on_translate_block_complete;
    sqi->events.on_translate_instruction_start = s2e_on_translate_instruction_start;
    sqi->events.on_translate_special_instruction_end = s2e_on_translate_special_instruction_end;
    sqi->events.on_translate_instruction_end = s2e_on_translate_instruction_end;
    sqi->events.on_translate_jump_start = s2e_on_translate_jump_start;
    sqi->events.on_translate_indirect_cti_start = s2e_on_translate_indirect_cti_start;
    sqi->events.on_translate_lea_rip_relative = s2e_on_translate_lea_rip_relative;
    sqi->events.on_translate_register_access = s2e_on_translate_register_access;
    sqi->events.on_call_return_translate = s2e_on_call_return_translate;

    sqi->log.debug = s2e_debug_print;
#endif
}
