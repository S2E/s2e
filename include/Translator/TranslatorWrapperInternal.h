///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <cassert>
#include <inttypes.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/Support/DynamicLibrary.h>
#include <stdlib.h>

extern "C" {
#include <cpu-all.h>
#include <exec-all.h>
#include <qemu-common.h>
}

#include "TranslatorWrapper.h"

s2e::S2EExecutionState *g_s2e_state = NULL;
s2e::S2E *g_s2e = NULL;

extern "C" {

static unsigned s_count = 0;

int g_s2e_fork_on_symbolic_address = 0;
int g_s2e_allow_custom_instructions = 0;

int execute_llvm = 0;
int generate_llvm = 0;
int kvm_allowed = 0;

int singlestep = 0;
int loglevel = 0;
int use_icount = 0;
int64_t qemu_icount = 0;
FILE *logfile = NULL;
CPUArchState *first_cpu;
CPUArchState *cpu_single_env;

CPUInterruptHandler cpu_interrupt_handler;

#define code_gen_section __attribute__((aligned(32)))
uint8_t code_gen_prologue[1024] code_gen_section;

// CPUWriteMemoryFunc *io_mem_write[IO_MEM_NB_ENTRIES][4];
// CPUReadMemoryFunc *io_mem_read[IO_MEM_NB_ENTRIES][4];
// void *io_mem_opaque[IO_MEM_NB_ENTRIES];

static int is_tb_instrumented(struct TranslationBlock *tb) {
    return 0;
}

static void increment_tb_stats(struct TranslationBlock *tb) {
    return;
}

static void set_tb_function(struct TranslationBlock *tb) {
    return;
}

static void on_privilege_change(unsigned previous, unsigned current) {
    return;
}

static void on_page_directory_change(uint64_t previous, uint64_t current) {
    return;
}

static void on_page_fault(uint64_t addr, int is_write, void *retaddr) {
    return;
}

static void on_tlb_miss(uint64_t addr, int is_write, void *retaddr) {
    return;
}

static void after_memory_access(uint64_t vaddr, uint64_t value, unsigned size, unsigned flags, uintptr_t retaddr) {
    return;
}

static void trace_port_access(uint64_t port, uint64_t value, unsigned bits, int isWrite, void *retaddr) {
    return;
}

static void tcg_execution_handler(void *signal, uint64_t pc) {
    return;
}

static void tcg_custom_instruction_handler(uint64_t arg) {
    return;
}

static void tcg_emit_custom_instruction(uint64_t arg) {
    return;
}

static void on_translate_soft_interrupt_start(void *context, struct TranslationBlock *tb, uint64_t pc,
                                              unsigned vector) {
    return;
}

static void on_translate_block_start(void *context, struct TranslationBlock *tb, uint64_t pc) {
    return;
}

static void on_translate_block_end(struct TranslationBlock *tb, uint64_t insPc, int staticTarget, uint64_t targetPc) {
    return;
}

static void on_translate_block_complete(struct TranslationBlock *tb, uint64_t pc) {
    return;
}

static void on_translate_instruction_start(void *context, struct TranslationBlock *tb, uint64_t pc) {
    return;
}

static void on_translate_special_instruction_end(void *context, struct TranslationBlock *tb, uint64_t pc,
                                                 enum special_instruction_t type, int update_pc) {
    return;
}

static void on_translate_instruction_end(void *context, struct TranslationBlock *tb, uint64_t pc, uint64_t nextpc) {
    return;
}

static void on_translate_jump_start(void *context, struct TranslationBlock *tb, uint64_t pc, int jump_type) {
    return;
}

static void on_translate_indirect_cti_start(void *context, struct TranslationBlock *tb, uint64_t pc, int rm, int op,
                                            int offset) {
    return;
}

static void on_translate_lea_rip_relative(void *context, struct TranslationBlock *tb, uint64_t pc, uint64_t addr) {
    return;
}

static void on_translate_register_access(struct TranslationBlock *tb, uint64_t pc, uint64_t readMask,
                                         uint64_t writeMask, int isMemoryAccess) {
    return;
}

static int on_call_return_translate(uint64_t pc, int isCall) {
    return 0;
}

// clang-format off
struct se_libcpu_interface_t g_sqi = {
    .tb = {
        .set_tb_function = set_tb_function,
        .is_tb_instrumented = is_tb_instrumented,
        .increment_tb_stats = increment_tb_stats
    },
    .events = {
        .before_memory_access_signals_count = &s_count,
        .after_memory_access_signals_count = &s_count,
        .on_translate_soft_interrupt_signals_count = &s_count,
        .on_translate_block_start_signals_count = &s_count,
        .on_translate_block_end_signals_count = &s_count,
        .on_translate_block_complete_signals_count = &s_count,
        .on_translate_instruction_start_signals_count = &s_count,
        .on_translate_special_instruction_end_signals_count = &s_count,
        .on_translate_jump_start_signals_count = &s_count,
        .on_translate_lea_rip_relative_signals_count = &s_count,
        .on_translate_instruction_end_signals_count = &s_count,
        .on_translate_register_access_signals_count = &s_count,
        .on_exception_signals_count = &s_count,
        .on_page_fault_signals_count = &s_count,
        .on_tlb_miss_signals_count = &s_count,
        .on_port_access_signals_count = &s_count,
        .on_privilege_change_signals_count = &s_count,
        .on_page_directory_change_signals_count = &s_count,
        .on_call_return_signals_count = &s_count,

        .on_privilege_change = on_privilege_change,
        .on_page_directory_change = on_page_directory_change,
        .on_page_fault = on_page_fault,
        .on_tlb_miss = on_tlb_miss,
        .after_memory_access = after_memory_access,
        .trace_port_access = trace_port_access,
        .tcg_execution_handler = tcg_execution_handler,
        .tcg_custom_instruction_handler = tcg_custom_instruction_handler,
        .tcg_emit_custom_instruction = tcg_emit_custom_instruction,

        .on_translate_soft_interrupt_start = on_translate_soft_interrupt_start,
        .on_translate_block_start = on_translate_block_start,
        .on_translate_block_end = on_translate_block_end,
        .on_translate_block_complete = on_translate_block_complete,
        .on_translate_instruction_start = on_translate_instruction_start,
        .on_translate_special_instruction_end = on_translate_special_instruction_end,
        .on_translate_instruction_end = on_translate_instruction_end,
        .on_translate_jump_start = on_translate_jump_start,
        .on_translate_indirect_cti_start = on_translate_indirect_cti_start,
        .on_translate_lea_rip_relative = on_translate_lea_rip_relative,
        .on_translate_register_access = on_translate_register_access,
        .on_call_return_translate = on_call_return_translate,
    }
};
// clang-format on

void *qemu_malloc(size_t s) {
    return malloc(s);
}

void *qemu_mallocz(size_t size) {
    void *ptr;
    ptr = qemu_malloc(size);
    memset(ptr, 0, size);
    return ptr;
}

void *qemu_realloc(void *ptr, size_t size) {
    return realloc(ptr, size);
}

void qemu_free(void *ptr) {
    free(ptr);
}

void qemu_init_vcpu(void *_env) {
}

extern "C" {
void target_disas(void *env, FILE *out, target_ulong code, target_ulong size, int flags) {
    assert(false && "Not usable statically");
}

void disas(void *env, FILE *out, void *code, unsigned long size) {
    assert(false && "Not usable statically");
}

const char *lookup_symbol(target_ulong orig_addr) {
    assert(false && "Not usable statically");
    return NULL;
}
}

TranslationBlock *tb_find_pc(uintptr_t tc_ptr) {
    assert(false && "Not usable statically");
    return NULL;
}

int s2e_is_tb_instrumented(TranslationBlock *tb) {
    return 0;
}

void s2e_increment_tb_stats(TranslationBlock *tb) {
}

int s2e_is_running_concrete() {
    return 0;
}

void s2e_set_tb_function(TranslationBlock *tb) {
}

void s2e_tcg_emit_custom_instruction(uint64_t arg) {
    assert(false && "Not usable statically");
}

void s2e_trace_port_access(uint64_t port, uint64_t value, unsigned bits, int isWrite, void *retaddr) {
    assert(false && "Not usable statically");
}

int s2e_is_port_symbolic(uint64_t port) {
    assert(false && "Not usable statically");
    return 0;
}

int se_is_mmio_symbolic(struct MemoryDesc *mr, uint64_t address, uint64_t size) {
    assert(false && "Not usable statically");
    return 0;
}

int se_is_mmio_symbolic_b(struct MemoryDesc *mr, uint64_t address) {
    assert(false && "Not usable statically");
    return 0;
}

int se_is_mmio_symbolic_w(struct MemoryDesc *mr, uint64_t address) {
    assert(false && "Not usable statically");
    return 0;
}

int se_is_mmio_symbolic_l(struct MemoryDesc *mr, uint64_t address) {
    assert(false && "Not usable statically");
    return 0;
}

int se_is_mmio_symbolic_q(struct MemoryDesc *mr, uint64_t address) {
    assert(false && "Not usable statically");
    return 0;
}

void s2e_on_translate_block_start(void *context, struct TranslationBlock *tb, uint64_t pc) {
}

void s2e_on_translate_block_end(struct TranslationBlock *tb, uint64_t insPc, int staticTarget, uint64_t targetPc) {
}

void s2e_on_translate_block_complete(struct TranslationBlock *tb, uint64_t pc) {
}

void s2e_on_translate_jump_start(void *context, struct TranslationBlock *tb, uint64_t pc, int jump_type) {
}

void s2e_on_translate_indirect_cti_start(void *context, TranslationBlock *tb, uint64_t pc, int rm, int op, int offset) {
}

void s2e_on_translate_instruction_start(void *context, struct TranslationBlock *tb, uint64_t pc) {
}

void s2e_on_translate_instruction_end(void *context, struct TranslationBlock *tb, uint64_t pc, uint64_t nextpc) {
}

void s2e_on_translate_lea_rip_relative(void *context, struct TranslationBlock *tb, uint64_t pc, uint64_t addr) {
}

void s2e_on_translate_special_instruction_end(void *context, struct TranslationBlock *tb, uint64_t pc,
                                              enum special_instruction_t type, int update_pc) {
}

void s2e_on_translate_register_access(struct TranslationBlock *tb, uint64_t pc, uint64_t readMask, uint64_t writeMask,
                                      int isMemoryAccess) {
}

void s2e_on_translate_soft_interrupt_start(void *context, struct TranslationBlock *tb, uint64_t pc, unsigned vector) {
}

void s2e_on_page_fault(uint64_t addr, int is_write, void *retaddr) {
    assert(false && "Not usable statically");
}

void s2e_on_page_directory_change(uint64_t previous, uint64_t current) {
}

void s2e_on_tlb_miss(uint64_t addr, int is_write, void *retaddr) {
    assert(false && "Not usable statically");
}

void s2e_after_memory_access(uint64_t vaddr, uint64_t value, unsigned size, unsigned flags, uintptr_t retaddr) {
    assert(false && "Not usable statically");
}

void s2e_read_register_concrete(unsigned offset, uint8_t *buf, unsigned size) {
    assert(false && "Not usable statically");
}

void s2e_write_register_concrete(unsigned offset, uint8_t *buf, unsigned size) {
    assert(false && "Not usable statically");
}

void s2e_write_ram_concrete(uint64_t host_address, const uint8_t *buf, uint64_t size) {
    assert(false && "Not usable statically");
}

void s2e_read_ram_concrete(uint64_t host_address, void *buf, uint64_t size) {
    assert(false && "Not usable statically");
}

void s2e_switch_to_symbolic(void *retaddr) {
    assert(false && "Not usable statically");
}

void s2e_read_ram_concrete_check(uint64_t host_address, uint8_t *buf, uint64_t size) {
    assert(false && "Not usable statically");
}

int s2e_on_call_return_translate(uint64_t pc, int isCall) {
    assert(false && "Not usable statically");
}

/***** CPU-RELATED WRAPPERS *****/
void cpu_outb(uint32_t addr, uint8_t val) {
    assert(false && "Not usable statically");
}

void cpu_outw(uint32_t addr, uint16_t val) {
    assert(false && "Not usable statically");
}

void cpu_outl(uint32_t addr, uint32_t val) {
    assert(false && "Not usable statically");
}

uint8_t cpu_inb(uint32_t addr) {
    assert(false && "Not usable statically");
    return 0;
}

uint16_t cpu_inw(uint32_t addr) {
    assert(false && "Not usable statically");
    return 0;
}

uint32_t cpu_inl(uint32_t addr) {
    assert(false && "Not usable statically");
    return 0;
}

int cpu_breakpoint_insert(CPUX86State *env, target_ulong pc, int flags, CPUBreakpoint **breakpoint) {
    assert(false && "Not usable statically");
}

int cpu_breakpoint_remove(CPUArchState *env, target_ulong pc, int flags) {
    assert(false && "Not usable statically");
}

void cpu_breakpoint_remove_all(CPUArchState *env, int mask) {
    assert(false && "Not usable statically");
}

void cpu_breakpoint_remove_by_ref(CPUArchState *env, CPUBreakpoint *breakpoint) {
    assert(false && "Not usable statically");
}

int cpu_watchpoint_insert(CPUArchState *env, target_ulong addr, target_ulong len, int flags,
                          CPUWatchpoint **watchpoint) {
    assert(false && "Not usable statically");
}

void cpu_watchpoint_remove_all(CPUArchState *env, int mask) {
    assert(false && "Not usable statically");
}

void cpu_watchpoint_remove_by_ref(CPUArchState *env, CPUWatchpoint *watchpoint) {
    assert(false && "Not usable statically");
}

void cpu_io_recompile(CPUArchState *env, void *retaddr) {
    assert(false && "Not usable statically");
}

uint64_t cpu_get_tsc(CPUX86State *env) {
    assert(false && "Not usable statically");
}

void cpu_loop_exit(CPUArchState *env) {
    assert(false && "Not usable statically");
}

void cpu_resume_from_signal(CPUArchState *env1, void *puc) {
    assert(false && "Not usable statically");
}

uint8_t cpu_get_apic_tpr(DeviceState *s) {
    assert(false && "Not usable statically");
}

void apic_handle_tpr_access_report(DeviceState *d, target_ulong ip, TPRAccess access) {
}

void cpu_set_ferr(CPUX86State *s) {
    assert(false && "Not usable statically");
}

void cpu_smm_update(CPUArchState *env) {
    assert(false && "Not usable statically");
}

CPUDebugExcpHandler *cpu_set_debug_excp_handler(CPUDebugExcpHandler *handler) {
    assert(false && "Not usable statically");
}

void cpu_abort(CPUArchState *env, const char *fmt, ...) {
    assert(false && "Not usable statically");
}

void cpu_set_apic_base(DeviceState *env, uint64_t val) {
    assert(false && "Not usable statically");
}

int cpu_memory_rw_debug(CPUArchState *env, target_ulong addr, uint8_t *buf, int len, int is_write) {
    assert(false && "Not usable statically");
}

uint64_t cpu_get_apic_base(DeviceState *env) {
    assert(false && "Not usable statically");
}

void cpu_exec_init(CPUArchState *env) {
    assert(false && "Not usable statically");
}

void cpu_set_apic_tpr(DeviceState *env, uint8_t val) {
    assert(false && "Not usable statically");
}

extern "C" {
void libcpu_system_reset_request(void) {
    assert(false && "Not usable statically");
}

/* Memory operations */
void stq_phys(target_phys_addr_t addr, uint64_t val) {
    assert(false && "Not usable statically");
}

void stl_phys(target_phys_addr_t addr, uint32_t val) {
    assert(false && "Not usable statically");
}

void stl_phys_notdirty(target_phys_addr_t addr, uint32_t val) {
}

void stw_phys(target_phys_addr_t addr, uint32_t val) {
    assert(false && "Not usable statically");
}

void stb_phys(target_phys_addr_t addr, uint32_t val) {
    assert(false && "Not usable statically");
}

uint64_t ldq_phys(target_phys_addr_t addr) {
    assert(false && "Not usable statically");
    return 0;
}

uint64_t ldq_kernel(target_phys_addr_t addr) {
    assert(false && "Not usable statically");
    return 0;
}

uint32_t ldl_phys(target_phys_addr_t addr) {
    assert(false && "Not usable statically");
    return 0;
}

uint32_t lduw_phys(target_phys_addr_t addr) {
    assert(false && "Not usable statically");
    return 0;
}

uint32_t ldub_phys(target_phys_addr_t addr) {
    assert(false && "Not usable statically");
    return 0;
}

uint64_t __ldq_cmmu(target_ulong addr, int mmu_idx) {
    assert(false && "Not usable statically");
    return 0;
}

uint32_t __ldl_cmmu(target_ulong addr, int mmu_idx) {
    assert(false && "Not usable statically");
    return 0;
}

uint16_t __ldw_cmmu(target_ulong addr, int mmu_idx) {
    assert(false && "Not usable statically");
    return 0;
}

uint8_t __ldb_cmmu(target_ulong addr, int mmu_idx) {
    assert(false && "Not usable statically");
    return 0;
}

int ldsb_data(target_ulong ptr) {
    assert(false && "Not usable statically");
    return 0;
}

int ldub_data(target_ulong ptr) {
    assert(false && "Not usable statically");
    return 0;
}

int ldub_kernel(target_ulong ptr) {
    assert(false && "Not usable statically");
    return 0;
}

int lduw_data(target_ulong ptr) {
    assert(false && "Not usable statically");
    return 0;
}

int lduw_kernel(target_ulong ptr) {
    assert(false && "Not usable statically");
    return 0;
}

int lduw_kernel_s2e_trace(target_ulong ptr) {
    assert(false && "Not usable statically");
    return 0;
}

int ldsw_data(target_ulong ptr) {
    assert(false && "Not usable statically");
    return 0;
}

int ldl_data(target_ulong ptr) {
    assert(false && "Not usable statically");
    return 0;
}

int ldl_kernel(target_ulong ptr) {
    assert(false && "Not usable statically");
    return 0;
}

int ldl_kernel_s2e_trace(target_ulong ptr) {
    assert(false && "Not usable statically");
    return 0;
}

int ldq_data(target_ulong ptr) {
    assert(false && "Not usable statically");
    return 0;
}

void stb_data(target_ulong ptr, uint8_t data) {
    assert(false && "Not usable statically");
}

void stb_kernel(target_ulong ptr, uint8_t data) {
    assert(false && "Not usable statically");
}

void stw_data(target_ulong ptr, uint16_t data) {
    assert(false && "Not usable statically");
}

void stw_kernel(target_ulong ptr, uint16_t data) {
    assert(false && "Not usable statically");
}

void stl_data(target_ulong ptr, uint32_t data) {
    assert(false && "Not usable statically");
}

void stl_kernel(target_ulong ptr, uint32_t data) {
    assert(false && "Not usable statically");
}

void stq_kernel(target_ulong ptr, uint32_t data) {
    assert(false && "Not usable statically");
}

void stq_data(target_ulong ptr, uint32_t data) {
    assert(false && "Not usable statically");
}
}

/*******************/
void tlb_flush_page(CPUArchState *env, target_ulong addr) {
}

int tlb_set_page_exec(CPUArchState *env, target_ulong vaddr, target_phys_addr_t paddr, int prot, int mmu_idx,
                      int is_softmmu) {
    return 0;
}

void tlb_flush(CPUArchState *env, int flush_global) {
}

void apic_init_reset(DeviceState *env) {
}

void apic_sipi(DeviceState *env) {
}

void helper_register_symbol(const char *name, void *address) {
    llvm::sys::DynamicLibrary::AddSymbol(name, address);
}

void run_on_cpu(CPUArchState *env, void (*func)(void *data), void *data) {
}

bool tcg_enabled(void) {
    return true;
}

void kvm_cpu_synchronize_state(CPUArchState *env) {
}

void do_interrupt_all(int intno, int is_int, int error_code, target_ulong next_eip, int is_hw) {
}

void tlb_set_page(CPUArchState *env, target_ulong vaddr, target_phys_addr_t paddr, int prot, int mmu_idx,
                  target_ulong size) {
}

int cpu_x86_register(CPUX86State *env, const char *cpu_model) {
}

void cpu_x86_cpuid(CPUX86State *env, uint32_t index, uint32_t count, uint32_t *eax, uint32_t *ebx, uint32_t *ecx,
                   uint32_t *edx) {
}

int cpu_is_bsp(CPUX86State *env) {
}

void s2e_on_privilege_change(unsigned previous, unsigned current) {
}
}
