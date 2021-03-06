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

#ifndef __QEMU_CPU_SE__

#define __QEMU_CPU_SE__

#include <inttypes.h>
#include <stdbool.h>

#include <cpu/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct TranslationBlock;

#if defined(TARGET_I386) || defined(TARGET_X86_64)
struct CPUX86State;
#define CPUArchState struct CPUX86State
#elif defined(TARGET_ARM)
struct CPUARMState;
#define CPUArchState struct CPUARMState
#else
#error Unsupported target architecture
#endif

typedef uintptr_t (*se_libcpu_tb_exec_t)(CPUArchState *env1, struct TranslationBlock *tb);
#if defined(TARGET_I386) || defined(TARGET_X86_64)
typedef void (*se_do_interrupt_all_t)(int intno, int is_int, int error_code, uintptr_t next_eip, int is_hw);
#elif defined(TARGET_ARM)
typedef void (*se_do_interrupt_arm_t)(void);
#else
#error Unsupported target architecture
#endif

#if defined(TARGET_I386) || defined(TARGET_X86_64)
void se_do_interrupt_all(int intno, int is_int, int error_code, target_ulong next_eip, int is_hw);
#elif defined(TARGET_ARM)
void se_do_interrupt_arm(void);
void se_set_armv7m_external_irq(int irq_num);
void se_enable_all_armv7m_external_irq(int serial);
void se_enable_systick_irq(int mode);
uint32_t se_get_active_armv7m_external_irq(int serial);

void se_helper_do_interrupt_arm(CPUArchState *env);
void se_helper_set_armv7m_external_irq(CPUArchState *env, int irq_num);
void se_helper_enable_all_armv7m_external_irq(CPUArchState *env, int serial);
void se_helper_enable_systick_irq(CPUArchState *env, int mode);
uint32_t se_helper_get_active_armv7m_external_irq(CPUArchState *env, int serial);
#else
#error Unsupported target architecture
#endif

#define MEM_TRACE_FLAG_IO 1
#define MEM_TRACE_FLAG_WRITE 2
#define MEM_TRACE_FLAG_PRECISE 4
#define MEM_TRACE_FLAG_PLUGIN 8

enum special_instruction_t { RDTSC, SYSENTER, SYSCALL, PUSHIM };

struct special_instruction_data_t {
    union {
        uint64_t immediate_value;
    };
};

struct se_libcpu_interface_t {
    unsigned size;

    /* Execution mode information */
    struct mode {
        const int *fast_concrete_invocation;
        const int *fork_on_symbolic_address;
        char **running_exception_emulation_code;
        const int *single_path_mode;
        const int *allow_custom_instructions;
        const int *concretize_io_writes;
        const int *concretize_io_addresses;
        const int *allow_interrupt;
    } mode;

    struct exec {
        void (*helper_register_symbol)(const char *name, void *address);

        void (*cleanup_tb_exec)(void);
        int (*finalize_tb_exec)(void);

        int (*is_yielded)(void);
        int (*is_runnable)(void);
        // XXX: May be redundant with **running_concrete above
        int (*is_running_concrete)(void);

        void (*reset_state_switch_timer)(void);
        void (*switch_to_symbolic)(void *retaddr) __attribute__((noreturn));

        se_libcpu_tb_exec_t tb_exec;
#if defined(TARGET_I386) || defined(TARGET_X86_64)
        se_do_interrupt_all_t do_interrupt_all;
#elif defined(TARGET_ARM)
        se_do_interrupt_arm_t do_interrupt_arm;
#else
#error Unsupported target architecture
#endif
        unsigned *clock_scaling_factor;
    } exec;

    /* TB management */
    struct tb {
        void *(*tb_alloc)(void);
        void (*flush_tb_cache)();
        void (*set_tb_function)(void *se_tb, void *llvmFunction);
        int (*is_tb_instrumented)(void *se_tb);
        void (*increment_tb_stats)(void *se_tb);
    } tb;

    /* TLB management */
    struct tlb {
        void (*flush_tlb_cache)(void);
        void (*flush_tlb_cache_page)(void *objectState, int mmu_idx, int index);
        void (*update_tlb_entry)(CPUArchState *env, int mmu_idx, uint64_t virtAddr, uint64_t hostAddr);
    } tlb;

    /* Register access */
    struct regs {
        void (*read_concrete)(unsigned offset, uint8_t *buf, unsigned size);
        void (*write_concrete)(unsigned offset, uint8_t *buf, unsigned size);
        void (*set_cc_op_eflags)(CPUArchState *state);
    } regs;

    /* Memory accessors */
    struct mem {
        uint8_t (*read_dirty_mask)(uint64_t host_address);
        void (*write_dirty_mask)(uint64_t host_address, uint8_t val);

        void (*dma_read)(uint64_t hostAddress, uint8_t *buf, unsigned size);
        void (*dma_write)(uint64_t hostAddress, uint8_t *buf, unsigned size);

        void (*read_ram_concrete)(uint64_t host_address, void *buf, uint64_t size);
        void (*write_ram_concrete)(uint64_t host_address, const uint8_t *buf, uint64_t size);
        void (*read_ram_concrete_check)(uint64_t host_address, uint8_t *buf, uint64_t size);

        uint64_t (*read_mem_io_vaddr)(int masked);
        int (*is_port_symbolic)(uint64_t port);
        int (*is_mmio_symbolic)(uint64_t phys_addr, unsigned size);
        int (*is_vmem_symbolic)(uint64_t vaddr, unsigned size);

        uintptr_t (*get_host_address)(uint64_t paddr);

        uint8_t (*__ldb_mmu_trace)(uint8_t *host_addr, target_ulong vaddr);
        uint16_t (*__ldw_mmu_trace)(uint16_t *host_addr, target_ulong vaddr);
        uint32_t (*__ldl_mmu_trace)(uint32_t *host_addr, target_ulong vaddr);
        uint64_t (*__ldq_mmu_trace)(uint64_t *host_addr, target_ulong vaddr);

        void (*__stb_mmu_trace)(uint8_t *host_addr, target_ulong vaddr);
        void (*__stw_mmu_trace)(uint16_t *host_addr, target_ulong vaddr);
        void (*__stl_mmu_trace)(uint32_t *host_addr, target_ulong vaddr);
        void (*__stq_mmu_trace)(uint64_t *host_addr, target_ulong vaddr);
    } mem;

    /* ExprInterface */
    struct expr {
        void *(*mgr)(void);
        void (*clear)(void *_mgr);
        void (*mgr_clear)(void);
        void *(*andc)(void *_mgr, void *_lhs, uint64_t constant);
        uint64_t (*to_constant)(void *expr);
        void (*set)(void *expr, uint64_t constant);
        void (*write_cpu)(void *expr, unsigned offset, unsigned size);
        void *(*read_cpu)(void *_mgr, unsigned offset, unsigned size);
        void *(*read_mem_l)(void *_mgr, uint64_t virtual_address);
        void *(*read_mem_q)(void *_mgr, uint64_t virtual_address);
    } expr;

    /* Internal functions in libcpu. */
    struct libcpu {
#if defined(TARGET_I386) || defined(TARGET_X86_64)
        uint32_t (*ldub_code)(struct CPUX86State *env, target_ulong virtual_address);
        uint32_t (*ldl_code)(struct CPUX86State *env, target_ulong virtual_address);
#elif defined(TARGET_ARM)
        uint32_t (*ldub_code)(struct CPUARMState *env, target_ulong virtual_address);
        uint32_t (*ldl_code)(struct CPUARMState *env, target_ulong virtual_address);
#else
#error Unsupported target architecture
#endif
    } libcpu;

    /* Core plugin interface */
    struct events {
        unsigned *before_memory_access_signals_count;
        unsigned *after_memory_access_signals_count;
        unsigned *on_translate_soft_interrupt_signals_count;
        unsigned *on_translate_block_start_signals_count;
        unsigned *on_translate_block_end_signals_count;
        unsigned *on_translate_block_complete_signals_count;
        unsigned *on_translate_instruction_start_signals_count;
        unsigned *on_translate_special_instruction_end_signals_count;
        unsigned *on_translate_jump_start_signals_count;
        unsigned *on_translate_lea_rip_relative_signals_count;
        unsigned *on_translate_instruction_end_signals_count;
        unsigned *on_translate_register_access_signals_count;
        unsigned *on_exception_signals_count;
        unsigned *on_exception_exit_signals_count;
        unsigned *on_page_fault_signals_count;
        unsigned *on_tlb_miss_signals_count;
        unsigned *on_port_access_signals_count;
        unsigned *on_privilege_change_signals_count;
        unsigned *on_page_directory_change_signals_count;
        unsigned *on_call_return_signals_count;
        unsigned *on_invalid_pc_access_signals_count;

        void (*on_privilege_change)(unsigned previous, unsigned current);
        void (*on_page_directory_change)(uint64_t previous, uint64_t current);
        void (*on_page_fault)(uint64_t addr, int is_write, void *retaddr);
        void (*on_tlb_miss)(uint64_t addr, int is_write, void *retaddr);

        void (*after_memory_access)(uint64_t vaddr, uint64_t value, unsigned size, unsigned flags, uintptr_t retaddr);

        void (*trace_port_access)(uint64_t port, uint64_t value, unsigned bits, int isWrite, void *retaddr);

        /* Translation events */
        void (*tcg_execution_handler)(void *signal, uint64_t pc);
        void (*tcg_custom_instruction_handler)(uint64_t arg);
        void (*tcg_emit_custom_instruction)(uint64_t arg);

        void (*on_translate_soft_interrupt_start)(void *context, struct TranslationBlock *tb, uint64_t pc,
                                                  unsigned vector);

        /** Called by cpu_gen_code() at the beginning of translation process */
        void (*on_translate_block_start)(void *context, struct TranslationBlock *tb, uint64_t pc);

        /** Called by cpu_gen_code() before the execution would leave the tb.
            staticTarget is 1 when the target pc at the end of the tb is known */
        void (*on_translate_block_end)(struct TranslationBlock *tb, uint64_t insPc, int staticTarget,
                                       uint64_t targetPc);

        /** Called when gen_intermediate_code_internal() returns */
        void (*on_translate_block_complete)(struct TranslationBlock *tb, uint64_t pc);

        /** Called by cpu_gen_code() before translation of each instruction */
        void (*on_translate_instruction_start)(void *context, struct TranslationBlock *tb, uint64_t pc);

        /** Called by cpu_gen_code() after translation of certain special types of instructions */
        void (*on_translate_special_instruction_end)(void *context, struct TranslationBlock *tb, uint64_t pc,
                                                     enum special_instruction_t type,
                                                     const struct special_instruction_data_t *data, int update_pc);

        /** Called by cpu_gen_code() after translation of each instruction */
        void (*on_translate_instruction_end)(void *context, struct TranslationBlock *tb, uint64_t pc, uint64_t nextpc);

        /** Called by cpu_gen_code() before translation of each jump instruction */
        void (*on_translate_jump_start)(void *context, struct TranslationBlock *tb, uint64_t pc, int jump_type);

        void (*on_translate_indirect_cti_start)(void *context, struct TranslationBlock *tb, uint64_t pc, int rm, int op,
                                                int offset);

        void (*on_translate_lea_rip_relative)(void *context, struct TranslationBlock *tb, uint64_t pc, uint64_t addr);

        void (*on_translate_register_access)(struct TranslationBlock *tb, uint64_t pc, uint64_t readMask,
                                             uint64_t writeMask, int isMemoryAccess);

        int (*on_call_return_translate)(uint64_t pc, int isCall);

        void (*on_invalid_pc_access)(uint64_t addr);

        void (*on_armv7m_interrupt_exit)(uint64_t irqNo);
    } events;

    struct {
        void (*debug)(const char *fmt, ...);
    } log;

    struct {
        int (*screendump)(const char *filename);
    } upcalls;
};

extern struct se_libcpu_interface_t g_sqi;

/******************************************************/
/* Prototypes for special functions used in LLVM code */
/* NOTE: this functions should never be defined. They */
/* are implemented as a special function handlers.    */

#if defined(SYMBEX_LLVM_LIB)
target_ulong tcg_llvm_fork_and_concretize(target_ulong value, target_ulong knownMin, target_ulong knownMax,
                                          target_ulong reason);

void tcg_llvm_before_memory_access(target_ulong vaddr, uint64_t value, unsigned size, unsigned flags);

void tcg_llvm_after_memory_access(target_ulong vaddr, uint64_t value, unsigned size, unsigned flags, uintptr_t retaddr);

uint64_t tcg_llvm_trace_mmio_access(uint64_t physaddr, uint64_t value, unsigned bytes, int isWrite);

void tcg_llvm_write_mem_io_vaddr(uint64_t value, int reset);

#if defined(TARGET_I386) || defined(TARGET_X86_64)
// XXX: change bits to bytes
uint64_t tcg_llvm_trace_port_access(uint64_t port, uint64_t value, unsigned bits, int isWrite);
uint64_t tcg_llvm_get_value(uint64_t value, bool addConstraint);
#endif

#endif

#ifdef __cplusplus
}
#endif

#endif
