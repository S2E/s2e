///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_LIBCPU_H
#define S2E_LIBCPU_H

#include <inttypes.h>
#include <stdarg.h>

#include "s2e_log.h"

#ifdef __cplusplus
namespace s2e {
struct S2ETranslationBlock;
}
using s2e::S2ETranslationBlock;
#else
struct S2E;
struct S2EExecutionState;
struct S2ETranslationBlock;
#endif

struct TranslationBlock;
struct TCGLLVMContext;
struct MemoryDesc;

// XXX
struct CPUX86State;

#ifdef __cplusplus
extern "C" {
#endif

struct PCIBus;

/**************************/
/* Functions from S2E.cpp */

/** Initialize S2E instance. Called by main() */
void s2e_initialize(int argc, char **argv, struct TCGLLVMContext *tcgLLVMContext, const char *s2e_config_file,
                    const char *s2e_output_dir, int setup_unbuffered_stream, int verbose, unsigned max_processes);

/** Relese S2E instance and all S2E-related objects. Called by main() */
void s2e_close(void);
void s2e_close_arg(void);
void *get_s2e(void);

#include "s2e_libcpu_coreplugin.h"

/**********************************/
/* Functions from S2EExecutor.cpp */

/** Global variable that determines whether to fork on
    symbolic memory addresses */
extern int g_s2e_fork_on_symbolic_address;

/** Global variable that determines whether to make
    symbolic I/O memory addresses concrete */
extern int g_s2e_concretize_io_addresses;

/** Global variable that determines whether to make
    symbolic I/O writes concrete */
extern int g_s2e_concretize_io_writes;

/** Prevent anything from flushing the TLB cache */
extern int g_se_disable_tlb_flush;

/** Fast check for cpu-exec.c */
extern int g_s2e_fast_concrete_invocation;

extern char *g_s2e_running_concrete;

extern char *g_s2e_running_exception_emulation_code;

extern uintptr_t g_se_dirty_mask_addend;

extern int g_s2e_single_path_mode;

/** Create initial S2E execution state */
void s2e_create_initial_state(void);

/** Initialize symbolic execution machinery. Should be called after
    libcpu pc is completely constructed */
void s2e_initialize_execution(int execute_always_klee);

void s2e_register_cpu(struct CPUX86State *cpu_env);

void s2e_register_ram(struct MemoryDesc *region, uint64_t start_address, uint64_t size, uint64_t host_address,
                      int is_shared_concrete, int save_on_context_switch, const char *name);

void s2e_register_ram2(const char *name, uint64_t host_address, uint64_t size, int is_shared_concrete);

uintptr_t se_get_host_address(uint64_t paddr);

void s2e_read_ram_concrete(uint64_t host_address, void *buf, uint64_t size);

void s2e_write_ram_concrete(uint64_t host_address, const uint8_t *buf, uint64_t size);

/** This function is called when RAM is read by concretely executed
    generated code. If the memory location turns out to be symbolic,
    this function will either concretize it of switch to execution
    in KLEE */
void s2e_read_ram_concrete_check(uint64_t host_address, uint8_t *buf, uint64_t size);

void s2e_read_register_concrete(unsigned offset, uint8_t *buf, unsigned size);

void s2e_write_register_concrete(unsigned offset, uint8_t *buf, unsigned size);

/* helpers that should be run as LLVM functions */
void s2e_set_cc_op_eflags(struct CPUX86State *state);

/** Allocate S2E parts of the tanslation block. Called from tb_alloc() */
void se_tb_alloc(struct TranslationBlock *tb);

/** Free S2E parts of the translation block. Called from tb_flush() and tb_free() */
void se_tb_free(struct TranslationBlock *tb);

/** Called after LLVM code generation
    in order to update tb->se_tb->llvm_function */
void s2e_set_tb_function(struct TranslationBlock *tb);

int s2e_is_tb_instrumented(struct TranslationBlock *tb);

void se_tb_gen_llvm(struct CPUX86State *env, struct TranslationBlock *tb);

void s2e_flush_tb_cache();
void s2e_increment_tb_stats(struct TranslationBlock *tb);
void s2e_flush_tlb_cache(void);
void se_flush_tlb_cache_page(void *objectState, int mmu_idx, int index);

extern se_libcpu_tb_exec_t se_libcpu_tb_exec;

/* Called by libcpu when execution is aborted using longjmp */
void s2e_libcpu_cleanup_tb_exec();

int s2e_libcpu_finalize_tb_exec(void);

void s2e_init_timers(void);

void s2e_init_device_state(void);

int s2e_is_zombie(void);
int s2e_is_speculative(void);
int s2e_is_yielded(void);
int s2e_is_runnable(void);
int s2e_is_running_concrete(void);

void s2e_reset_state_switch_timer(void);

void s2e_execute_cmd(const char *cmd);

// Used by port IO for now
void s2e_switch_to_symbolic(void *retaddr) __attribute__((noreturn));

void se_ensure_symbolic(void);

int s2e_is_port_symbolic(uint64_t port);
int s2e_is_mmio_symbolic(uint64_t physaddr, unsigned size);
int se_is_mmio_symbolic(struct MemoryDesc *mr, uint64_t address, uint64_t size);
int se_is_mmio_symbolic_b(struct MemoryDesc *mr, uint64_t address);
int se_is_mmio_symbolic_w(struct MemoryDesc *mr, uint64_t address);
int se_is_mmio_symbolic_l(struct MemoryDesc *mr, uint64_t address);
int se_is_mmio_symbolic_q(struct MemoryDesc *mr, uint64_t address);

void s2e_update_tlb_entry(struct CPUX86State *env, int mmu_idx, uint64_t virtAddr, uint64_t hostAddr);

void s2e_register_dirty_mask(uint64_t host_address, uint64_t size);
uint8_t se_read_dirty_mask(uint64_t host_address);
void se_write_dirty_mask(uint64_t host_address, uint8_t val);

void s2e_dma_read(uint64_t hostAddress, uint8_t *buf, unsigned size);
void s2e_dma_write(uint64_t hostAddress, uint8_t *buf, unsigned size);

void s2e_on_privilege_change(unsigned previous, unsigned current);
void s2e_on_page_directory_change(uint64_t previous, uint64_t current);

void s2e_on_initialization_complete(void);

int s2e_is_load_balancing();
int s2e_is_forking();

void se_setup_precise_pc(struct TranslationBlock *tb);
void s2e_fix_code_gen_ptr(struct TranslationBlock *tb, int code_gen_size);

void se_tb_safe_flush(void);

/******************************************************/
/* Prototypes for special functions used in LLVM code */
/* NOTE: this functions should never be defined. They */
/* are implemented as a special function handlers.    */

#if defined(SYMBEX_LLVM_LIB)
target_ulong tcg_llvm_fork_and_concretize(target_ulong value, target_ulong knownMin, target_ulong knownMax,
                                          target_ulong reason);

void tcg_llvm_before_memory_access(target_ulong vaddr, uint64_t value, unsigned size, unsigned flags);

void tcg_llvm_after_memory_access(target_ulong vaddr, uint64_t value, unsigned size, unsigned flags, uintptr_t retaddr);

uint64_t tcg_llvm_trace_port_access(uint64_t port, uint64_t value, unsigned bits, int isWrite);

uint64_t tcg_llvm_trace_mmio_access(uint64_t physaddr, uint64_t value, unsigned bytes, int isWrite);

void tcg_llvm_write_mem_io_vaddr(uint64_t value, int reset);
void tcg_llvm_make_symbolic(void *addr, unsigned nbytes, const char *name);
void tcg_llvm_get_value(void *addr, unsigned nbytes, bool addConstraint);
#endif

uint64_t s2e_read_mem_io_vaddr(int masked);

void s2e_kill_state(const char *message);

/* Register target-specific helpers with LLVM */
void helper_register_symbols(void);
void helper_register_symbol(const char *name, void *address);

#ifdef __cplusplus
}
#endif

#endif // S2E_LIBCPU_H
