# Replacing the execution layer with QEMU 11.1's `accel/tcg`

The execution layer is the part of libcpu between the KVM shim and the
instruction decoder. It contains the CPU loop (`cpu_exec()`), the cache of
translation blocks and its lookup, the chaining of blocks, the generation of a
block (`tb_gen_code()`), the invalidation of blocks when the guest writes to
its own code, the flush of the whole cache, and the reconstruction of the guest
state from a host address inside generated code. It also defines the interface
through which it asks the frontend (the x86 decoder in `target-i386/translate.c`)
to translate a block.

libcpu still has the QEMU 1.0 version of all of this, except the softmmu, which
was replaced by upstream's `cputlb.c` (`softmmu-update.md`). This document is
the plan for replacing the rest with upstream's `accel/tcg` at `v11.1.0`, and
for adapting the QEMU 1.0 frontend to upstream's translator interface
(`TCGCPUOps.translate_code` and `translator_loop()`). The frontend keeps its
decoder and its S2E instrumentation. Replacing the decoder itself is the next
step (`PORTING.md` phase 3), and this plan is meant to leave nothing else for
that step to change in the layers around it.

`PORTING.md` schedules most of this work in phase 2 and the translator
interface in phase 3. This plan does both together and before the frontend, for
the same reason the softmmu was ported alone: the execution layer is where most
of S2E's hooks into libcpu live, and it is easier to validate them on a
frontend whose behavior is known than in the middle of the 31k-line frontend
import.

Measured against `~/softs/qemu` at `v11.1.0` and this tree at `40509541`.

**Status: in progress.** Steps 1, 2 and 2b are done. Step 3 is committed, but
its exit criteria have not all been checked (10.3). Nothing else in this
document has landed.

The plan therefore does not try to be complete: section 10 says how each
step checks what the plan may have missed, and how the plan is updated when the
code disagrees with it. A statement marked *(unverified)* was not checked
against the code. Everything else was checked against the tree and `v11.1.0`
when it was written.

Terms used below:

- **TB** (translation block): a sequence of guest instructions translated as a
  unit, with its host code and metadata (`TranslationBlock`).
- **Chaining**: patching the exit of one TB to jump directly into the next one,
  so that the CPU loop is not entered between them (`tb_add_jump()`).
- **Jump cache**: a small per-CPU table indexed by the guest virtual PC that
  short-cuts the TB hash lookup.
- **qht**: QEMU's concurrent hash table, which holds all TBs in upstream. It is
  already imported in libutils, together with **RCU** (read-copy-update), the
  memory reclamation scheme it uses.
- **SMC** (self-modifying code): a guest store into a page that holds
  translated code.
- **LLVM TB**: a TB that, in addition to its host code, has an LLVM function
  that KLEE can interpret (`tb->llvm_function`). Only S2E builds have them.
- **Native** and **KLEE** execution: running a TB's host code directly, or
  interpreting its LLVM function in KLEE. Symbolic data can only be handled by
  the second.


## 1. The execution layer today

| File | Lines | Role |
|---|---:|---|
| `src/cpu-exec.c` | 602 | CPU loop, TB lookup (`tb_find_fast()`, `tb_find_slow()`), interrupt and exception processing, TB execution and S2E dispatch |
| `src/exec-tb.{c,h}` | 689 | TB allocation, flush, physical page lists, invalidation (including SMC), jump lists and chaining |
| `src/exec-phystb.{c,h}` | 117 | The physical page table (`PageDesc`, `l1_map`) that `exec-tb.c` hangs TBs on |
| `src/translate-all.c` | 235 | `tcg_exec_init()`, `cpu_gen_code()`: one call to the frontend and to `tcg_gen_code()`, plus the LLVM translation |
| `src/precise-pc.c` | 221 | Copies of upstream's `encode_search()` and `cpu_restore_state()`, plus the S2E-only `tb_get_instruction_size()` |
| `src/exec-bp.c` (part) | ~75 | The watchpoint hit check (`cpu_watchpoint_address_matches()`, `cpu_check_watchpoint()`); the breakpoint functions and the watchpoint insertion and removal stay |
| `src/exec-all.h` (part) | ~100 | Declarations, the hash functions and the `tb_phys_hash` table |
| `include/cpu/tb.h` | 69 | Jump cache geometry and the TB functions that libs2e and libs2ecore call |
| `libtcg/include/tcg/tb.h` | 169 | `TranslationBlock`: a QEMU 1.0 base (`phys_hash_next`, `page_next`) with 11.1's jump fields and the S2E fields added |

The frontend interface is `gen_intermediate_code(env, tb)`
(`target-i386/translate.c:7935`). The frontend runs its own loop over
instructions, reads code with `cpu_ld*_code()`, emits its own exit-request
check (`gen_tb_start()` and `gen_tb_end()` at `translate.c:7700`, under the
S2E flag `CF_HAS_INTERRUPT_EXIT`), and checks breakpoints at every
instruction. `cpu_gen_code()` sets the per-block `TCGContext` fields and runs
the LLVM translator after `tcg_gen_code()`. `tb_gen_code()` computes the second
physical page of the block after translation.

### 1.1 What S2E does in this layer

Everything in this table must survive the replacement. Section 3 says where
each item goes.

| # | Behavior | Today |
|---|---|---|
| S1 | Leave the CPU loop with `EXCP_SE` when the current state is not runnable, without normalizing EFLAGS (S11) | `cpu_exec()` entry and its longjmp branch, `g_sqi.exec.is_runnable()`. On entry, a yielded state also gets `g_sqi.exec.reset_state_switch_timer()`. |
| S2 | Finish the interpretation of a TB that a state switch interrupted, and clean up the KLEE stack after a longjmp | `g_sqi.exec.finalize_tb_exec()` after each `setjmp()`, followed by `g_sqi.exec.cleanup_tb_exec()` when it returns true; `g_sqi.exec.cleanup_tb_exec()` after each longjmp |
| S3 | Run a TB natively or in KLEE | `fetch_and_run_tb()`: `fast_concrete_invocation` selects `tcg_qemu_tb_exec()` or `g_sqi.exec.tb_exec()`; `se_tb_abort` and `se_current_tb` are set around the call. `g_sqi.exec.tb_exec()` runs the TB in KLEE and returns 0, runs it natively and returns what `tcg_qemu_tb_exec()` returned, or returns `SE_TB_EXEC_DECLINED` without running it when it needs an LLVM function (S4). |
| S4 | Generate an LLVM function when KLEE needs one | `generate_llvm` in `CPUState`; the lookup rejects a TB without `llvm_function`; `cpu_gen_code()` calls `tcg_llvm_gen_code()` and `g_sqi.tb.set_tb_function()` |
| S5 | Attach an `S2ETranslationBlock` to every TB | `tb_alloc()` calls `g_sqi.tb.tb_alloc()`; `cpu_gen_code()` allocates a new one when it retries a block that was too large; `tb->instrumented` is set after translation |
| S6 | Tell libs2ecore about a flush | `tb_flush()` calls `g_sqi.tb.flush_tb_cache()` |
| S7 | Defer a flush requested while a TB runs | `se_tb_safe_flush()` sets a flag that the next lookup consumes |
| S8 | Do not chain from a TB that a flush or invalidation removed | `tb_invalidated_flag` |
| S9 | Stop the current TB after it overwrote its own code | `tb_invalidate_phys_page_range()`: natively, advance `eip` past the store and patch the TB's host code to exit (`tcg_target_force_tb_exit()`); in KLEE, set `se_tb_abort`, which the LLVM code tests at each instruction |
| S10 | Leave the loop when the KVM client's interrupt window opens | `execution_loop()`, after each TB: `kvm_request_interrupt_window`, IF set and no interrupt shadow |
| S11 | Store EFLAGS in its standard form when the loop exits | end of `cpu_exec()`: `g_sqi.regs.set_cc_op_eflags()`, or `cpu_cc_compute_all()` without symbex |
| S12 | Do not report a halt when an interrupt is already pending | `cpu_exec()`: `EXCP_HLT` with `interrupt_request` set clears `halted` and continues |
| S13 | Never recompile the current TB at an MMIO access | `can_do_io` is always true. The CPU state is therefore not committed while libs2e handles the access (`s2e-kvm-vcpu.h:135-163`). |
| S14 | Give plugins the size of an instruction inside a TB | `tb_get_instruction_size()`, which decodes the search data that `encode_search()` writes |
| S15 | Log the loop | `CPU_LOG_EXEC` and `CPU_LOG_INT` lines, `dump_regs()` with symbolic registers read through `g_sqi.regs` |

Some things in the old code have no remaining purpose and are deleted rather
than ported: `current_tb` (it served the signal-time unchaining that upstream
replaced with `icount_decr`, and only assertions and one save and restore in
`S2EExecutionState.cpp` still read it), `translate_single_instruction` (its only
setter is the disabled `ENABLE_RETRANSLATE` block in `s2e-kvm-io.cpp`),
`g_cpu_stats`, `cpu_single_env`, `cpu_resume_from_signal()`,
`cpu_set_debug_excp_handler()`, `se_restore_state_to_opc()`,
`restore_state_to_next_pc()` and the `gen_intermediate_code_pc()`,
`cpu_gen_flush()`, `cpu_gen_init_opc()` and `tb_free()` declarations.


## 2. Target shape

### 2.1 Files

Imported from `v11.1.0` through `normalize.sh`, each with a row in
`libcpu/scripts/upgrade/mapping.tsv` (or libtcg's, where noted):

| Upstream | libcpu path | Lines | Note |
|---|---|---:|---|
| `accel/tcg/cpu-exec.c` | `src/accel/cpu-exec.c` | 1,090 | Deviations D1 to D5, D12 |
| `accel/tcg/cpu-exec-common.c` | `src/accel/cpu-exec-common.c` | 91 | Include lines changed |
| `accel/tcg/tb-maint.c` | `src/accel/tb-maint.c` | 1,225 | Deviations D7, D8 |
| `accel/tcg/translate-all.c` | `src/accel/translate-all.c` | 638 | Deviation D6; includes `s2e/translate-all-symbex.c.inc` |
| `accel/tcg/translator.c` | `src/accel/translator.c` | 522 | Deviations D9, D10 |
| `accel/tcg/watchpoint.c` | `src/accel/watchpoint.c` | 142 | Deviation D11; replaces the watchpoint hit check of `exec-bp.c` |
| `accel/tcg/{tb-context,tb-internal,internal-common}.h` | `src/accel/` | 248 | Include lines changed |
| `accel/tcg/{tb-hash,tb-jmp-cache}.h` | `src/accel/` | 98 | Imported in step 2b item 4; include lines changed |
| `include/exec/translator.h` | `include/cpu/exec/translator.h` | 282 | |
| `include/exec/tb-flush.h` | `include/cpu/exec/tb-flush.h` | 38 | C++ guards added |
| `include/accel/tcg/cpu-loop.h` | `include/cpu/accel/cpu-loop.h` | 73 | C++ guards added |
| `include/accel/tcg/tb-cpu-state.h` | `include/cpu/accel/tb-cpu-state.h` | 22 | Imported in step 2 item 9, which needs `TCGTBCPUState` |
| `include/exec/translation-block.h` | libtcg `include/tcg/exec/translation-block.h` | 217 | libtcg mapping; S2E fields appended (2.2) |

About 4,600 lines arrive. They replace `cpu-exec.c`, `exec-tb.{c,h}`,
`exec-phystb.{c,h}`, the old `translate-all.c`, `precise-pc.c` and its public
header `include/cpu/precise-pc.h`, the watchpoint hit check of `exec-bp.c`, most of
`exec-all.h` and libtcg's `tcg/tb.h`, about 2,200 lines. `cpu/tb.h` shrinks to
the declarations that libs2e and libs2ecore use, and takes over the two
declarations of `precise-pc.h` that they still need:
`cpu_restore_state(CPUState *, uintptr_t)` and `tb_get_instruction_size()`.
`cpu/exec.h` stops including `precise-pc.h`.

Each file enters the tree in two commits. The first adds the output of
`normalize.sh` and the `mapping.tsv` row, with no S2E change, and is not
built yet. The second makes the S2E changes: the deviations of section 3, the
include fixes that `normalize.sh` does not do, and the build integration.
`git diff` between the two commits then shows exactly what S2E changed, and
the next upgrade can diff the normalized upstream text of the new tag against
the first commit without having to separate S2E changes from upstream code.
The same rule applies to `translation-block.h` in libtcg.

S2E-original files:

- `src/s2e/accel-deps.h`: `cputlb-deps.h`, which step 2b item 6 renamed. The
  list below is what
  was found before implementation; the compiler and the checks of section 10
  find the rest.
  - **Added** for the new files: `current_cpu`, the trace-point, plugin,
    replay and icount stubs, `runstate_is_running()`, and the BQL (Big QEMU
    Lock) no-ops. Also the exclusive-section functions that
    `cpu_exec_step_atomic()` and `tb_flush__exclusive_or_serial()` reference
    (`start_exclusive()`, `end_exclusive()`, `cpu_in_exclusive_context()`),
    `cpu_test_interrupt()`, `cpu_single_stepping()` (over
    `singlestep_flags`, as upstream) and `lookup_symbol()`. `current_cpu` is
    defined in `exec.c` next to `first_cpu`, and `one_insn_per_tb` and
    `icount_align_option` in `tcg-init.c`, because `internal-common.h`
    declares them `extern`. Step 4 adds `target_disas()`. Upstream's
    `target_disas()` takes a `DisasContextBase`, and only the fallback
    disassembly of `translator_loop()` calls it, which does not run because
    the frontend provides `disas_log`. The stub can therefore do nothing.
    `runstate_is_running()` returns false, so that the assertion at the top
    of `tb_flush__exclusive_or_serial()` holds. `async_safe_run_on_cpu()`,
    which `queue_tb_flush()` calls, already exists for `cputlb.c`.
    `qemu_log_in_addr_range()` and `qemu_log_trylock()` already exist in
    libtcg's `tcg.h` and must not be defined again. The replay stubs must
    return the values that keep upstream on its normal path, for example
    `replay_exception()` true, or `cpu_handle_exception()` stops delivering
    exceptions.
  - **Changed** in step 2b: `CPU_FOREACH` visits the single CPU, so that
    `tb_flush__exclusive_or_serial()` and `tb_jmp_cache_inval_tb()` do not
    leave jump cache entries that point to flushed TBs. The three
    `CPU_FOREACH` loops of `cputlb.c` now run, and all three skip the source
    CPU, so they still do nothing. The `qemu_spin_*` macros only apply to the
    bitcode build. Native code uses the real functions of `utils/thread.h`,
    where an uncontended `qemu_spin_trylock()` reports success, so
    `tb_lock_page1()` does not take the restart path of hazard 5.6. No S2E hook
    that runs with the TLB lock held re-enters the TLB, throws or longjmps.
  - **Removed**, because the new files define the real ones: the TB shims
    (`tb_invalidate_phys_range_fast()`), the `cpu_loop_exit_atomic()` and
    `cpu_io_recompile()` macros, which would rewrite the definitions in
    `cpu-exec-common.c` and `translate-all.c` (`accel-deps.h:152` and
    `:165`), and the inline `cpu_in_serial_context()` and
    `cpu_plugin_mem_cbs_enabled()`, which `internal-common.h` also defines.
    `accel-deps.h` includes `internal-common.h`, so `cputlb.c` gets it as
    upstream's does, and it compiles in the bitcode build. The stale
    declaration `cpu_io_recompile(CPUArchState *, void *)` in `exec-all.h:74`
    goes too. `cputlb.c:2424` is in the part of the file that is compiled to
    bitcode and calls `cpu_loop_exit_atomic()`, so removing the macro makes
    the bitcode reference the native function (hazard 5.3).
  - **Logging** (hazard 5.11): `CPU_LOG_TB_NOCHAIN`, `CPU_LOG_TB_FPU` and
    `CPU_LOG_TB_VPU` are defined as 0, like `CPU_LOG_MMU` today.
- `src/s2e/cpu-exec-symbex.c.inc`: the S2E functions that D1 to D5 call,
  included at the end of `cpu-exec.c` so that they can use its static
  functions, as `cputlb-symbex.c.inc` does for `cputlb.c`.
- `src/s2e/translate-all-symbex.c.inc`: `tb_get_instruction_size()` (S14),
  written over `translate-all.c`'s static `decode_sleb128()` so that the search
  data format has one definition.
- `src/s2e/tcg-init.c`: `tcg_exec_init()` and the `TCGContext` fields that
  libtcg's backend and LLVM translator read (`env_offset_*`, `tlb_fast_offset`,
  `page_bits`, `addr_type`, ...). These are set once at init instead of per
  TB. libtcg only reads them (`tcg_func_start()` does not reset them).
  `addr_type` must be set here because the adapter of step 3 does not go
  through `translator_loop()`, which sets it upstream. `tcg_exec_init()` also
  does what upstream's `tcg_init_machine()` does before `tcg_init()`: it sets
  `tcg_allowed` and calls `page_init()` and `tb_htable_init()`. Without the
  last call, the qht is used uninitialized.
  The file also holds `tcg_exec_cpu_init()`, which replaces the call to
  upstream's `tcg_exec_realizefn()`. libcpu does not call
  `tcg_exec_realizefn()` because it would call `tlb_init()` a second time
  (`cpu_exec_init()` already does) and set up the IOMMU notifiers.
  `tcg_exec_cpu_init()` asserts the hooks that `tcg_exec_realizefn()` asserts
  (`translate_code` from step 3 on, when the hook exists),
  calls `tcg_ops->initialize()` the first time, allocates `cpu->tb_jmp_cache`
  as upstream does, and sets `cflags_next_tb` to -1 (2.2).
  `cpu_x86_init()` (`helper.c:1091`) calls it where it calls
  `optimize_flags_init()` today, but outside the `inited` test, because the
  jump cache and `cflags_next_tb` belong to the CPU.
- `src/target-i386/tcg-cpu.c`: the x86 `TCGCPUOps` (2.3), native only. It
  takes the name of upstream's `target/i386/tcg/tcg-cpu.c` so that phase 3
  replaces it. The four softmmu hooks it references stay in `op_helper.c`,
  which the bitcode build needs (`softmmu-update.md` 2.4).

None of the new files is compiled to bitcode. The bitcode build reaches this
layer only through native functions that KLEE already calls by name
(`cpu_loop_exit()`, `cpu_restore_state()`, `notdirty_write()`, `tlb_flush()`,
...), registered with `__DEFINE_EXT_FUNCTION` in `S2EExecutor.cpp`.

### 2.2 Data structures

**`TranslationBlock`** becomes upstream's, in libtcg, because libtcg's
`tcg.c`, `region.c` and `tcg-llvm.cpp` read it and libtcg cannot depend on
libcpu. This settles the ownership question of `PORTING.md` section 8 ("Two
components, one struct"). The S2E fields go in one `#ifdef CONFIG_SYMBEX`
block at the end: `llvm_function`, `se_tb`, `se_tb_type`, `se_tb_call_eip`,
`pcOfLastInstr` and `instrumented`. `enum ETranslationBlockType` and
`enum JumpType` move to an S2E header in libtcg (`tcg/tb-s2e.h`). Visible
changes for libs2ecore and the plugins:

- `flags` is `uint32_t` instead of `uint64_t`. x86 TB flags are `hflags` plus
  the IOPL, TF, RF and VM fields of EFLAGS, and already fit:
  `cpu_get_tb_cpu_state()` returns them in an `int`.
- `icount` is `uint16_t`, which holds `TCG_MAX_INSNS` (512).
- `phys_hash_next` is gone. `page_addr[]` is read through `tb_page_addr0()`
  and `tb_page_addr1()`.
- `tb_page_addr_t` is `ram_addr_t` instead of libtcg's `uintptr_t`,
  `page_next[]` holds tagged `uintptr_t` values instead of pointers, and
  `jmp_lock` is a `QemuSpin` instead of an `int`. `tcg/tb-s2e.h` defines
  `ram_addr_t` for libtcg and libcpu, because libtcg cannot include libcpu.
  During step 2, the old `exec-tb.c` runs on this struct and is adapted to the
  three types.
- Upstream's header includes `qemu/thread.h`, `exec/cpu-common.h`,
  `exec/vaddr.h` and `system/ram_addr.h`. libs2ecore and the plugins include it
  from C++. `qemu/thread.h` is libutils' `utils/thread.h`. Only `CPUState` is
  needed from `exec/cpu-common.h`, and the header declares it. `vaddr.h` moves
  from libcpu to libtcg. The header compiles with g++ and clang++ with and
  without `CONFIG_SYMBEX`.
- The `CF_*` values are upstream's. `CF_COUNT_MASK` is `0x1ff`, which
  `TCG_MAX_INSNS` already matches. `CF_HAS_INTERRUPT_EXIT` disappears: every
  TB checks for an exit request unless it has `CF_NOIRQ`, so the test in
  `tcg-llvm.cpp:1371` becomes `!(tb->cflags & CF_NOIRQ)`. `CF_NOCACHE` is
  gone too, together with its one-shot path in `cpu_restore_state()`.

**`CPUState`** (`include/cpu/state.h`) gains the fields that the new files
read and loses the dead ones:

| Field | Change | Snapshotted | Why |
|---|---|---|---|
| `tcg_cflags` | added | yes (constant) | Base `cflags` of every TB; S2E builds set `CF_NO_GOTO_PTR` (decision 4.4) |
| `cflags_next_tb` | added | yes | Forces the `cflags` of the next TB: one instruction after SMC, a watchpoint hit or a breakpoint page. A pending request belongs to the state that made it. -1 means no request. `tcg_exec_cpu_init()` sets it to -1, because `cpu_x86_init()` allocates the CPU with `g_malloc0()` and `cpu_common_reset()` only runs on an INIT interrupt. With 0, the first TB would get `cflags` 0 instead of `curr_cflags()`. `cpu_common_reset()` also sets it to -1. |
| `tb_jmp_cache` | added, pointer | yes (constant) | Points at the `CPUJumpCache` that `tcg_exec_cpu_init()` allocates |
| `singlestep_enabled` | kept | yes | `cpu_single_stepping()` reads it |
| `singlestep_flags` | added | yes | `cpu_handle_interrupt()` tests `SSTEP_NOIRQ` in it. The old loop tested that bit in `singlestep_enabled`. Nothing calls `cpu_single_step()`, the only writer of `singlestep_enabled`, so both stay 0. |
| `jmp_env` | type `sigjmp_buf` | carried across switches | Upstream uses `sigsetjmp()`/`siglongjmp()`. glibc defines `jmp_buf` and `sigjmp_buf` as the same type, so libs2ecore's `setjmp()`/`longjmp()` on it keep working. |
| `current_tb`, `translate_single_instruction` | removed | | Section 1.1 |
| `mem_io_pc` | kept | yes | Upstream's `CPUState` still has it, and `io_prepare()` in `cputlb.c` stores into it. Removing it would add a deviation to `cputlb.c`. Nothing reads it once the `ENABLE_RETRANSLATE` block is deleted. |
| `exit_request` | kept | yes | Read by `cpu_handle_interrupt()`, no longer by generated code |

**`CPUNegativeOffsetState`** gains `IcountDecr icount_decr`, which upstream's
`gen_tb_start()` reads at a fixed negative offset from `env` at the start of
every TB. Upstream's `cpu_exit()` (`hw/core/cpu-common.c`, not imported) only
sets `exit_request` and calls `qemu_cpu_kick()`. The store of -1 into the high
half of `icount_decr`, which makes the next TB exit, is done by
`tcg_kick_vcpu_thread()`. libcpu's `cpu_exit()` does both stores itself, in
the order of `tcg_kick_vcpu_thread()`: first `exit_request`, then
`icount_decr.u16.high`, both with `qatomic_store_release()`. A TB that sees
the high half set then also sees `exit_request`.

Upstream's `cpu_interrupt()` sets the high half too. libcpu's does not, and
the plan keeps that: an interrupt request reaches the loop when libs2e calls
`cpu_exit()`, as today. Adopting upstream's behavior changes when an interrupt
stops a chain of TBs and is a separate change.

`icount_decr` does not need to be snapshotted. `cpu_handle_interrupt()` clears
the high half each time it runs, which is every iteration of the loop except
the one that follows a request for a `CF_NOIRQ` TB (after SMC, decision 4.1).
A stale value therefore costs at most two extra trips through the loop. The
old `tb_jmp_cache` array leaves `neg`. Upstream's cache stores the PC next to
each TB pointer, so it grows from 32 KB to 64 KB. It lives on the heap and is
not snapshotted. All the code that clears it in `cputlb.c` is in the
native-only part of the file, so the bitcode never reads the pointer.

**`CPUWatchpoint`** and the `BP_*` flags become upstream's, because
`watchpoint.c` reads `wp->len`, `wp->hitaddr` and `wp->hitattrs` and records
hits with `BP_HIT_SHIFT`. libcpu's struct has `len_mask` instead of `len`, and
its `BP_WATCHPOINT_HIT` is a single bit (0x08) where upstream's is the two hit
bits `BP_WATCHPOINT_HIT_READ` and `BP_WATCHPOINT_HIT_WRITE` (0xc0). The
watchpoint insertion and removal functions that stay in `exec-bp.c` store
`len` instead of `len_mask`, and `hw_breakpoint` code in `helper.c` (`:999`)
keeps testing `BP_WATCHPOINT_HIT`, whose meaning does not change.

**`TCGContext.cpu`** is a `CPUX86State *` in libtcg (`tcg.h:481`), and
upstream's `setjmp_gen_code()` stores a `CPUState *` into it. Nothing in
libtcg reads the field, so it changes to `struct CPUState *`.

**`CPUClass`** gains `get_pc` and `set_pc`. `get_pc` is called by `log_pc()`
for `CF_PCREL` TBs and by the `CPU_LOG_EXEC` line of `cpu_io_recompile()`.
`set_pc` is called by `cpu_tb_exec()` when there is no `synchronize_from_tb`.
libcpu reaches none of them: it has no `CF_PCREL` TBs, provides
`synchronize_from_tb`, and never calls `cpu_io_recompile()` (decision 4.3).
Both are written over `env->eip` and `segs[R_CS].base`.

The old `CPUArchState *first_cpu` becomes a `CPUState *` and
`CPU_FOREACH(cpu)` visits it. `cpu_single_env` is removed, together with its
`__DEFINE_EXT_OBJECT_RO` in `S2EExecutor.cpp:495`. The frontend reads
`s->env` instead (`translate.c:6914` and `:6932`).

`EXCP_SE` moves from `0x10004`, which is upstream's `EXCP_YIELD`, to
`0x10006`, and `interrupt.h` defines `EXCP_YIELD` and `EXCP_ATOMIC` with
upstream's values. `CPU_INTERRUPT_RESET` is imported from upstream's
`cpu-interrupt.h` (0x0400), together with its numbering of the
`CPU_INTERRUPT_TGT_INT_*` bits. As in upstream's `target/i386/cpu.h`,
`CPU_INTERRUPT_INIT` becomes an alias of `CPU_INTERRUPT_RESET`. No x86 bit
changes value.

`target-i386/cpu.h:359` defines `cpu_exec` as `cpu_x86_exec`. The macro is
deleted: it would rename upstream's `cpu_exec()` to the name of the wrapper of
decision 4.6.

These libcpu functions have the name of an upstream function that the new
files call, with a QEMU 1.0 signature. The list was built by comparing the
calls of the new files with libcpu's declarations. The comparison did not
cover macros or types, so the compiler may find more.

- `cpu_reset_interrupt(CPUArchState *, int)` (`exec.c:118`) changes to take
  a `CPUState *`, as `cpu_handle_interrupt()` expects.
- `cpu_interrupt(CPUArchState *, int)` (`cpu-all.h:258`) changes to take a
  `CPUState *`, as `cpu_check_watchpoint()` in `watchpoint.c` expects. Its
  behavior does not change (2.2, `icount_decr`).
- `cpu_abort(CPUArchState *, const char *, ...)` (`exec.c:126`) changes to
  take a `CPUState *`, as `cpu_io_recompile()` in `translate-all.c` expects.
- `cpu_dump_state(CPUArchState *, FILE *, fprintf_function, int)`
  (`helper.c:329`) becomes `cpu_dump_state(CPUState *, FILE *, int)`, which
  `log_cpu_exec()` calls. Its callers go through `log_cpu_state()` in libtcg's
  `log.h` and through `exec.c:136-138`.
- The old `target_disas(env, out, pc, size, flags)` (`disas.c:95`) is renamed
  `target_disas_range()`, together with the `log_target_disas()` macro that
  calls it, so that `accel-deps.h` can define upstream's `target_disas()`.

### 2.3 The x86 `TCGCPUOps`

`s_x86_tcg_ops` moves to `target-i386/tcg-cpu.c` and gains the hooks of the
CPU loop and the translator. Each one is written over existing QEMU 1.0 code,
so the step changes where the code is called from, not what it does.

| Hook | Written from |
|---|---|
| `initialize` | `optimize_flags_init()` (`translate.c:7665`), which `helper.c:1091` calls once at CPU init today. `tcg_exec_cpu_init()` (2.1) calls the hook instead. |
| `translate_code` | `gen_intermediate_code()`, then the `translator_loop()` adapter of 2.4 |
| `get_tb_cpu_state` | `cpu_get_tb_cpu_state()`, returning a `TCGTBCPUState` |
| `synchronize_from_tb` | `execution_loop()`'s `env->eip = ltb->pc - ltb->cs_base` for `TB_EXIT_REQUESTED` |
| `restore_state_to_opc` | `restore_state_to_opc()` (`translate.c:7955`), taking `const uint64_t *data` |
| `cpu_exec_enter` | none: libcpu keeps the flags in `mflags` and `cc_src`/`cc_op` already |
| `cpu_exec_exit` | the EFLAGS normalization at the end of `cpu_exec()` (S11). In S2E builds, it does nothing when `g_sqi.exec.is_runnable()` is false. `cpu_exec_setjmp()` calls the hook (D12) after `cpu_exec_loop()` returns, including the `EXCP_SE` return of D2, and the old loop skips the normalization on that return. The state is then yielded or a zombie, which is exactly when `is_runnable()` is false. |
| `do_interrupt` | `do_interrupt()` |
| `cpu_exec_interrupt` | `process_interrupt_request()`, without the `DEBUG` and `EXITTB` cases that upstream's `cpu_handle_interrupt()` handles itself. It keeps the `CPU_LOG_INT` lines and `cpu_get_pic_interrupt()`, which reaches libs2e's interrupt sources. |
| `cpu_exec_halt` | `cpu_has_work()` |
| `cpu_exec_reset` | the `CPU_INTERRUPT_INIT` case: `svm_check_intercept(SVM_EXIT_INIT)`, `do_cpu_init()`, then `exception_index = EXCP_HALTED`. The hook returns instead of calling `cpu_loop_exit()`, as upstream's `x86_cpu_exec_reset()` does: `cpu_handle_interrupt()` returns true after it, and `cpu_handle_exception()` then returns `EXCP_HALTED` from `cpu_exec()`. A longjmp would also go through the cleanup of D2 for no reason. Nothing in libcpu or libs2e raises INIT today. |
| `debug_excp_handler` | `breakpoint_handler()` in `helper.c`, which today registers itself with `cpu_set_debug_excp_handler()` |
| `debug_check_breakpoint` | the frontend's per-instruction check: a `BP_CPU` breakpoint does not fire while `RF` is set in `mflags` |
| `debug_check_watchpoint` | none; the generic code then reports every hit |
| `precise_smc` | `true` (decision 4.1) |
| `guest_default_memory_order` | `TCG_MO_ALL` through steps 3 and 4, the value that `cpu_gen_code()` uses today because libcpu does not define `TCG_GUEST_DEFAULT_MO`. This keeps the generated code unchanged during the switch. Upstream's x86 value, `TCG_MO_ALL & ~TCG_MO_ST_LD`, is a separate change (hazard 5.12). |

### 2.4 The QEMU 1.0 frontend on `translator_loop()`

`DisasContext` embeds `DisasContextBase base` as its first member, which
replaces its `tb` and `is_jmp` fields. `DisasContext.pc` stays: it is the
decoder's read position, which `disas_insn()` advances on every byte it
fetches, and upstream's i386 `DisasContext` keeps the same field next to
`base.pc_next`. `x86_translate_code()` calls `translator_loop()` with the
callbacks below, then does what the old function did after its loop.

| Callback | Old code it receives |
|---|---|
| `init_disas_context` | The `dc` setup and the per-TB temporaries (`cpu_T[]`, `cpu_A0`, `cpu_tmp*`) from `gen_intermediate_code_internal()`; the S2E `dc` fields (`instrument`, `enable_jmp_im`, `cpuState`), `tb->se_tb_type = TB_DEFAULT` and `tb->se_tb_call_eip = 0` |
| `tb_start` | The store of `tb` into `se_current_tb` and `on_translate_block_start`. Upstream emits the exit-request check before calling it, as the old `gen_tb_start()` did. |
| `insn_start` | The per-instruction S2E code in the old order: `dc->insPc`, `done_instr_end` and `done_reg_access_end`, then `on_translate_instruction_start`, then `tb->pcOfLastInstr`, `useNextPc` and `nextPc`. Then `tcg_gen_insn_start(pc, cc_op, 0)`, moved out of `disas_insn()`. The event stays before the marker, as today, so that instrumentation code is attributed to the same instruction as before. The marker must be the last op the callback emits: `translator_loop()` records it with `tcg_last_op()`. |
| `translate_insn` | `disas_insn()`, the register-access mask, and `gen_instr_end()` when the instruction does not end the TB. It stores the address of the next instruction in `base.pc_next`, from which `translator_loop()` computes `tb->size`. It ends the TB with `DISAS_TOO_MANY` when the old loop would have stopped for single-step, `TF`, `HF_INHIBIT_IRQ_MASK` or the page limit (`pc - pc_first >= TARGET_PAGE_SIZE - 32`). |
| `tb_stop` | For `DISAS_TOO_MANY`: `gen_jmp_im()`, `gen_eob_event()` and `gen_eob()`, the code both of the old loop's stop branches emit. Nothing for `DISAS_NORETURN`. |
| `disas_log` | `log_target_disas()` (capstone) |
| after `translator_loop()` | `tb->se_tb_type = TB_EXCP` for an invalid instruction, and `on_translate_block_complete`. Both need `tb->size`, which `translator_loop()` sets after `tb_stop`. |

The old `is_jmp` values map simply: the only one the frontend sets is
`DISAS_TB_JUMP`, and always after emitting its own exit (`gen_eob()`,
`gen_goto_tb()`), so it becomes `DISAS_NORETURN`. The old `DISAS_JUMP` and
`DISAS_UPDATE` macros are unused and are deleted, which also removes the
collision between the old `DISAS_JUMP` (1) and upstream's `DISAS_TOO_MANY`.

`translator_loop()` replaces three things the frontend did itself:

- **The exit-request check.** `gen_tb_start()` and `gen_tb_end()` are deleted
  from `translate.c`. Upstream's check loads `neg.icount_decr.u32` and branches
  if it is negative. `removeInterruptExit()` (`tcg-llvm.cpp:1205`) still
  finds that branch as the terminator of the first block, because the S2E
  instrumentation of `tb_start` comes after it.
- **The breakpoint check.** The per-instruction loop over `cpu->breakpoints`
  is deleted. Upstream checks in the CPU loop (`check_for_breakpoints()`), and
  limits TBs on a page with a breakpoint to one instruction (`CF_BP_PAGE`).
  These TBs also get `CF_NO_GOTO_TB`, so that every instruction on the page
  returns to the loop and its check. A direct jump on such a page must not chain to the next TB, which would skip
  the check. `gen_goto_tb()` and `jmp_opt` must therefore test
  `CF_NO_GOTO_TB`, as upstream's `translator_use_goto_tb()` does, and do since
  step 2b item 2. libtcg's `tcg_gen_goto_tb()` also asserts that the flag is
  clear (`tcg-op.c:2309`), but that `tcg_debug_assert()` is not compiled in
  release or debug builds, so a missing test would go unnoticed.
- **The instruction limit.** `max_insns` comes from `translator_loop()`, which
  takes it from `cflags`. `translate_single_instruction` was the last other
  source.

Code fetches go through `translator_ld{ub,uw,l,q}()`. This is required, not
cosmetic: upstream's `tb_gen_code()` no longer computes the second physical
page of a TB, and `translator_ld()` records it when the frontend first reads
from that page. With `cpu_ld*_code()`, a TB that crosses a page would only be
linked to its first page, and a write to the second page would not invalidate
it. The 85 call sites in `translate.c` take a `DisasContext` already and change
mechanically, except the two `cpu_ldsw_code()` calls (`translate.c:6167` and
`:6203`). Upstream has no signed variant, so they become
`(int16_t) translator_lduw()`.


## 3. S2E deviations in the imported files

Each one gets a comment that states why, so that the next merge can keep it.
The numbers in parentheses refer to section 1.1. These are the deviations
known before implementation. Deviations found later are added with the next
free number, and a deviation that turns out unnecessary is marked as dropped
rather than renumbered (section 10).

- **D1. TB dispatch** (S3), in `cpu_tb_exec()`. The call to
  `tcg_qemu_tb_exec()` becomes a call to `se_tb_exec()`, which clears
  `se_tb_abort`, sets `se_current_tb`, calls `tcg_qemu_tb_exec()` or
  `g_sqi.exec.tb_exec()` depending on `fast_concrete_invocation`, and clears
  `se_current_tb`. Before `tcg_qemu_tb_exec()`, it clears
  `**g_sqi.mode.running_exception_emulation_code`, as the old loop does.
  `g_sqi.exec.tb_exec()` clears that flag itself, but the fast path does not
  go through it. Under `CPU_LOG_EXEC`, `se_tb_exec()` also calls `dump_regs()`
  before and after the TB (S15). `dump_regs()` moves to
  `cpu-exec-symbex.c.inc` unchanged, because it reads symbolic registers
  through `g_sqi.regs`, which upstream's `log_cpu_exec()` does not. `g_sqi.exec.tb_exec()` has three outcomes (S3), and
  upstream's `cpu_tb_exec()` handles each one as the old loop did. A TB that
  KLEE ran returns 0, so `last_tb` is NULL and the loop does not chain from
  it. A TB that it declined to run because it needs an LLVM function
  returns `SE_TB_EXEC_DECLINED`, with `eip` unchanged. `se_tb_exec()` turns that
  into 0, and D3 regenerates the TB at the next lookup. A
  TB that it ran natively returns the value of `tcg_qemu_tb_exec()`, which the
  loop chains from or passes to `synchronize_from_tb` like any native exit.
  A declined TB needs one more thing. The loop has already consumed
  `cflags_next_tb` when it looked the TB up, so the next lookup would use
  `curr_cflags()` and translate a full TB instead of the one-instruction TB
  that SMC or a watchpoint hit asked for. For a guest data breakpoint in KLEE,
  the debug exception would then arrive at the end of that full TB, because
  libcpu's `cpu_interrupt()` does not stop a running TB. `g_sqi.exec.tb_exec()`
  therefore returns `SE_TB_EXEC_DECLINED` for a declined TB, and `se_tb_exec()`
  sets `cflags_next_tb` back to `tb->cflags` and returns 0. Step 2b item 5 has
  this code on the old loop already.
- **D2. Entry and longjmp** (S1, S2). `cpu_exec()` returns `EXCP_SE` after
  `cpu_handle_halt()` when the state is not runnable, the order of the old
  code. Before returning, it calls `reset_state_switch_timer()` if the state
  is yielded. These returns come before `cpu_exec_enter()`, so
  `cpu_exec_exit()` does not run. The longjmp branch of `cpu_exec_setjmp()`
  calls `cleanup_tb_exec()` after `cpu_exec_longjmp_cleanup()` and returns
  `EXCP_SE` if the state is no longer runnable. `cpu_exec_loop()` starts by
  calling `finalize_tb_exec()`. When that returns true, it calls
  `cleanup_tb_exec()`, then returns `EXCP_SE` if `exception_index` is
  `EXCP_SE`. Otherwise it continues into `cpu_handle_exception()`, as the old
  loop did after its `continue`. Upstream calls `cpu_exec_loop()` both on
  entry and after every longjmp, which are exactly the two places where the
  old loop re-armed `setjmp()` and called `finalize_tb_exec()`. The return
  from the longjmp branch skips `cpu_exec_exit()`. The return from
  `cpu_exec_loop()` reaches it (D12), and the hook skips the EFLAGS
  normalization for a state that is not runnable (2.3).
- **D3. LLVM TBs** (S4), in `cpu_exec_loop()` after `tb_lookup()`. When
  `generate_llvm` is set and the TB that was found has no `llvm_function`,
  `tb_phys_invalidate()` removes it and the loop generates a new one
  (decision 4.2). `tb_gen_code()` runs the LLVM translator (D6).
- **D4. Deferred flush and stale chaining** (S7, S8), in `cpu_exec_loop()`.
  A pending `se_tb_safe_flush()` request is carried out before
  `tb_lookup()`. Just before `tb_add_jump()`, `last_tb` is cleared if
  `tb_ctx.tb_flush_count` changed since just before the previous TB started,
  which also covers a flush while that TB ran. The check must
  come after `tb_gen_code()` and not before the lookup. libcpu never sets
  `CF_PARALLEL`, so `tb_gen_code()` flushes inline when the code buffer is
  full (`tb_flush__exclusive_or_serial()`, then `goto buffer_overflow`)
  instead of leaving the loop. A check before the lookup would miss that
  flush, and `tb_add_jump()` would patch a TB in the reset code buffer. One
  check at that place covers both flushes. Upstream's loop has no equivalent
  of `tb_invalidated_flag` on these paths. Invalidation of a single TB needs
  nothing: `tb_add_jump()` refuses a destination with `CF_INVALID`, and an
  invalidated source has the low bit of its `jmp_dest[]` set.
- **D5. Interrupt window** (S10), in `cpu_exec_loop()` after
  `cpu_loop_exec_tb()`, the same place as today. When the window has opened,
  it sets `exception_index` to `EXCP_INTERRUPT` and leaves the inner loop, so
  that `cpu_handle_exception()` returns from `cpu_exec()`. Checking before the
  lookup instead would be closer to KVM, which exits before executing anything
  when the window is already open, but it changes when libs2e reports
  `KVM_EXIT_IRQ_WINDOW_OPEN` and is a separate change.
- **D6. TB generation** (S4, S5), in `tb_gen_code()`. After
  `tcg_tb_alloc()`: `llvm_function = NULL` and a new `se_tb`. This also covers
  the retries through `goto buffer_overflow` (code buffer full during code
  generation or `encode_search()`), which allocate a new TB after the flush.
  Before each `goto restart_translate`: a new `se_tb`, because the plugins
  attached their signals to the old one during the failed attempt. After
  `encode_search()`:
  the LLVM translation when `generate_llvm` is set, and `tb->instrumented`.
  The discard path for an existing TB needs nothing: `S2EExecutor` keeps every
  `S2ETranslationBlock` until the next flush.
- **D7. Flush hook** (S6), at the top of `tb_flush__exclusive_or_serial()`:
  `g_sqi.tb.flush_tb_cache()`. libcpu keeps exporting `tb_flush(CPUState *)`
  for libs2ecore and the plugins, as a wrapper in `src/s2e/`. It must not be
  called while a TB runs, because `tcg_region_reset_all()` makes the code
  buffer of the running TB available for new translations. Three plugin call
  sites do exactly that, from an instruction handler, and then throw
  `CpuExitException`: `WindowsMonitor.cpp:432` and `:854`, and
  `TBCoverageTracer.cpp:129`. They switch to `se_tb_safe_flush()`, which has
  the same effect for them: the flush happens before the next lookup, and no
  TB runs in between. The remaining caller, `S2EExecutor::flushTb()`, runs at
  shutdown, outside the CPU loop.
- **D8. SMC in KLEE** (S9), in `tb_invalidate_phys_page_range__locked()`.
  Upstream detects that the current TB was overwritten only when it has the
  host return address of the store. A store made by KLEE has none: the LLVM
  translator passes 0 (`tcg-llvm.cpp:613`). In that case, with a CPU, the
  deviation sets `se_tb_abort` whenever it invalidates a TB, as the old code
  does (`exec-tb.c:400-406`). The LLVM code tests the flag at the next
  instruction boundary, after storing the next `eip`, and returns. Native code
  does not test the flag, and `se_tb_exec()` clears it before each TB, so a
  native store from a helper that passes no return address only sets a flag
  that nothing reads. The callers of hazard 5.9 pass no CPU and do not set it,
  as the old callers with `is_cpu_write_access` 0 did not.
  Limiting the abort to the TB in `se_current_tb` would avoid needless aborts,
  but `se_current_tb` does not reliably name the running TB while
  `finalize_tb_exec()` finishes a TB of a resumed state. The field is
  snapshotted, and `se_tb_exec()` clears it only when a TB returns normally. A
  state that was switched out in the middle of a TB, or after a longjmp out of
  one, therefore resumes with a pointer to that TB, which may have been flushed
  since. A state that was switched out after a normal return resumes with NULL.
  The narrower test could miss SMC in the TB that `finalize_tb_exec()` finishes.
- **D9. Code fetches in S2E builds**, in `translator_ld()` and the four
  `translator_ld*()` functions. In symbex builds, `translator_ld()` does its
  page bookkeeping (the second page, its lock, the MMIO cap) and then returns
  false, so that the caller reads through `cpu_ld*_code_mmu()`. That is the
  path the old frontend uses today. The fast path reads through a host pointer
  derived from `addend`, which is wrong in two ways in S2E. In multi-path
  builds the active state's copy of the page is reached through `se_addend`,
  not `addend`. And a code page that holds symbolic bytes has `TLB_SYMB` on
  its code comparator so that the slow path concretizes them
  (`softmmu-update.md` deviation 10), which a direct read skips. The callers
  also skip `record_save()` in symbex builds: the record holds one
  instruction, and it would overflow when every read takes the slow path.
  Only `translator_st()` reads the record, and its one caller in this layer,
  the fallback disassembly of `translator_loop()`, does not run because the
  frontend provides `disas_log`.
- **D10. `can_do_io`**, in `translator_loop()`: the two `set_can_do_io()`
  stores are not emitted, so `can_do_io` stays true (decision 4.3).
- **D11. One-instruction TB of a watchpoint hit**, in `cpu_check_watchpoint()`:
  the request also has `CF_NO_GOTO_TB`. Upstream's second pass through the check
  calls `cpu_interrupt()`, which stops a chain of TBs. libcpu's does not (2.2),
  so a TB that chains (a `call` that pushes to a watched stack slot, for
  example) would deliver the debug exception late.
- **D12. `cpu_exec_exit()`**, called from `cpu_exec_setjmp()` instead of
  `cpu_exec()`. When the flags are symbolic, the hook runs
  `helper_set_cc_op_eflags` in KLEE. If that helper forks, `setCCOpEflags()`
  longjmps to `jmp_env`. In upstream's place, the frame that called
  `sigsetjmp()` has already returned.

`cpu-exec-common.c` and the five headers in `src/accel/` differ from upstream
only in their include lines.


## 4. Decisions

### 4.1 Self-modifying code: adopt upstream's behavior in native execution

When natively executed code overwrites its own TB, the old code lets the store
complete, advances `eip` past the instruction, and patches the TB's host code
so that it returns to the loop (`exec-tb.c:409-421`, `tcg_target_force_tb_exit()`
in libtcg's x86_64 backend). Upstream restores the state to the storing
instruction, invalidates the TBs, sets `cflags_next_tb` to one instruction with
`CF_NOIRQ`, and longjmps out before the store happens. The store then executes
again in a one-instruction TB.

Recommendation: take upstream's behavior. It removes the only place where
libcpu rewrites generated code at run time, and `tcg_target_force_tb_exit()`
with it. The visible difference is that the instrumentation of the storing
instruction runs twice: its instruction-start signals and any memory access
that precedes the store in the same instruction. A store that page-faults
already behaves this way today, so plugins see nothing new in kind. KLEE keeps
the current behavior through D8.

### 4.2 LLVM TBs: one TB per key, regenerated on demand

The old lookup skips a TB without an LLVM function when `generate_llvm` is set
and generates a second TB for the same key. The new one is inserted at the
head of the hash chain, so the old one is never found again. The qht cannot
hold two TBs with the same key: `tb_link_page()` returns the existing TB and
`tb_gen_code()` discards the new one.

Recommendation: D3. Invalidate the TB without an LLVM function, then generate.
This keeps one TB per key, which is what the old code achieves in practice,
and the invalidation unlinks the jumps into the old TB so that chained code
reaches the new one.

The alternative is an S2E bit in `cflags`. `cflags` is part of the hash key, so
native lookups would no longer find the LLVM TB and each mode would translate
its own copy. This doubles the translations around every switch between
concrete and symbolic execution, and the old code shares one TB between them.

### 4.3 `can_do_io`: keep it true for now

In 11.1, `translator_loop()` clears `can_do_io` before the first
instruction of a TB and sets it before the last one. An MMIO access from any
other instruction calls `cpu_io_recompile()`, which longjmps and re-executes
the instruction in a one-instruction TB, so that the CPU state is precise
at every MMIO access.

This would fix the inconsistency that `s2e-kvm-vcpu.h:135-163` documents: the
KVM client can read the registers during an MMIO exit while the CPU state is
not committed. But in KLEE it breaks: a bitcode access to a device page reaches
the native `do_ld_mmio_beN()` (`softmmu-update.md`, step 2 of
`softmmu-llvm-perf.md`) with a return address of 0, and `cpu_io_recompile()`
aborts when it cannot find a TB. It also changes TB boundaries at every
MMIO access, which plugins observe.

Recommendation: D10 for this plan. Enabling it is a separate change with its
own testing: `io_prepare()` must skip the recompile when the return address is
0, and the LLVM code would have to keep `can_do_io` coherent with the
instruction being interpreted.

### 4.4 `goto_ptr`: disabled in S2E builds

The old frontend never emits `lookup_and_goto_ptr`, and
`helper_lookup_tb_ptr()` aborts (`helper.c:1121`). Upstream's
`HELPER(lookup_tb_ptr)` comes with `cpu-exec.c`. The new frontend uses it for
every indirect jump.

`goto_ptr` jumps into the next TB without returning to the loop, so it would
also bypass the decisions S2E makes per TB in `executeTranslationBlock()`
(`S2EExecutor.cpp:1104`): starting symbolic execution at a given PC, running a
TB in KLEE because a register became symbolic, generating LLVM code. Direct
chaining (`goto_tb`) already bypasses them today, but only for targets known
at translation time. The LLVM translator has no `goto_ptr` case either.

Recommendation: S2E builds set `CF_NO_GOTO_PTR` in `tcg_cflags`, which makes
`tcg_gen_lookup_and_goto_ptr()` emit a plain `exit_tb`. The plain
`{i386,x86_64}-softmmu` builds get `goto_ptr` with the new frontend. Enabling
it in S2E builds needs `lookup_tb_ptr` to return to the loop whenever S2E has
a reason to stop, and `tcg-llvm.cpp` to handle the op.

### 4.5 Breakpoints: upstream's loop check

Recommendation: delete the frontend's per-instruction check and use
`check_for_breakpoints()` with `debug_check_breakpoint` (2.3). The semantics
are the same: `EXCP_DEBUG` at the breakpoint's PC, with `RF` suppressing
`BP_CPU` breakpoints. The guest's hardware breakpoints (DR0-DR7) are `BP_CPU`
breakpoints, so this path is exercised by any guest that uses a debugger, and
is checked in step 4. The check relies on the frontend honoring
`CF_NO_GOTO_TB` (2.4).

### 4.6 HLT with a pending interrupt: keep it out of `cpu-exec.c`

S12 is not a loop property: upstream returns `EXCP_HLT` and the caller decides
what to do. libs2e's caller, `VCPU::coroutineFcn()`, therefore becomes the
place for it, through a wrapper `cpu_x86_exec(CPUArchState *)` in
`src/s2e/` that libs2e already calls by that name. The wrapper:

- sets `exception_index` to -1 before calling `cpu_exec()`. The old
  `cpu_exec()` did this on entry, and libs2e sets the field to 0 after each
  call (`s2e-kvm-vcpu.cpp:337`). Upstream does not reset it, and would take
  the 0 for a pending divide error (hazard 5.1);
- calls `cpu_exec()` again, after clearing `halted`, when it returns `EXCP_HLT`
  while `interrupt_request` is set;
- clears `exit_request` just before it returns to libs2e, as upstream's
  callers do after `cpu_exec()` (`system/cpus.c`). The old loop cleared it
  only when it left the loop because of it. After an `EXCP_HLT` return or an
  interrupt window exit (D5), a pending request survived and made the next
  `cpu_exec()` return at once. The wrapper drops such a request instead. This
  does not lose an exit, because the wrapper is returning to libs2e, which is
  what the request asked for. The clear must not happen before the retry of
  the previous point: the guest keeps running after the retry, so a request
  made during the first call would be lost. The old loop kept it across its
  `continue`.

The last point keeps the old behavior exactly, including waking up for an
interrupt that `IF` masks. Upstream's `cpu_exec_halt` would stay halted in
that case. Whether libcpu should follow is a separate question.

### 4.7 RCU: the vCPU thread stays unregistered

`cpu_exec()` holds an RCU read-side section for its whole duration
(`RCU_READ_LOCK_GUARD()`). In libs2e, `cpu_exec()` runs in a coroutine that
yields back to the KVM client on every I/O exit, with the section still open.
A registered thread in a read-side section delays every grace period, so if
the vCPU thread were registered, the `call_rcu` thread could not free the old
qht bucket arrays until `cpu_exec()` returned.

The vCPU thread is not registered today, and should stay so. With a single
thread doing all lookups and all modifications of the TB hash, the read-side
sections protect nothing: no other thread can free memory that the vCPU thread
is reading. libutils' `rcu.c` registers the `call_rcu` thread and the thread
that runs its constructor, which is the KVM client's main thread at preload
time. The symbols stay local to `libs2e.so` (`libs2e/src/mapfile`), so they
do not collide with the client's own RCU.

In a forked child, `rcu_init_child()` (`pthread_atfork()`) recreates the
`call_rcu` thread, which S2E's process forks rely on, and registers the thread
that called `fork()`. In S2E that is the vCPU thread: `doLoadBalancing()`
forks from the state switch timer, which `libcpu_run_all_timers()` runs
between two `cpu_exec()` calls (`s2e-kvm-vcpu.cpp:327`). This has two
consequences:

- `rcu_register_thread()` asserts that the thread is not in a read-side
  section. A fork from inside `cpu_exec()` would abort the child, so process
  forks must stay outside `cpu_exec()`.
- In a child, the vCPU thread is registered, and the old qht bucket arrays
  are freed only when `cpu_exec()` returns. Nothing waits for that grace
  period on the vCPU thread, so this delays memory reclamation but cannot
  deadlock.


## 5. Hazards

**5.1 `exception_index` has to be -1 on entry.** Upstream's loop starts by
processing `exception_index` when it is not negative. libs2e writes 0 into it
after every `cpu_exec()` (`s2e-kvm-vcpu.cpp:337`), which upstream would deliver
as interrupt 0. The wrapper of 4.6 resets it. Removing the write in libs2e is
the cleaner fix and can be done in the same change.

**5.2 `jmp_env` is armed once per `cpu_exec()` call.** The old loop called
`setjmp()` at every iteration, so any code that overwrote `jmp_env` was
corrected at the next iteration. Upstream calls `sigsetjmp()` once in
`cpu_exec_setjmp()` and longjmps to it any number of times. Two S2E paths
write the field: `executeTranslationBlockConcrete()` saves and restores it
around its own `setjmp()` on both paths, and `doStateSwitch()` copies the
current one over the restored snapshot. Both are correct, but any new writer
must restore it, or the next longjmp returns into a dead frame.

**5.3 The bitcode build must not start calling native code KLEE does not
know.** Deleting the TB shims of `accel-deps.h` turns inline code into calls
to `tb-maint.c` and `translate-all.c`. Wherever `cputlb.c`'s bitcode build
reaches them, they must be registered with `__DEFINE_EXT_FUNCTION`, or KLEE
stops with an unresolved external. Check the undefined symbols of
`op_helper.bc` after any change to this code. The bitcode reaches TB
invalidation only through `notdirty_write()`, which is native and registered.
`cputlb.c` calls `cpu_loop_exit_atomic()` from code compiled to bitcode, so
`S2EExecutor.cpp` registers it. libcpu never sets `CF_PARALLEL`, so the call is
not reached. It was the only new native reference that step 3 added.

**5.4 `icount_decr` is read by both code generators.** The native exit check
reads `neg.icount_decr.u32` at a negative offset from `env`. The LLVM
function contains the same load. `removeInterruptExit()` replaces the branch
with a direct branch and then erases the compare and the load, which have no
other users, so KLEE never reads `neg` memory for this check. It also asserts
that the branch it erases is that check (`icmp slt` of an `i32` load from
the CPU state, against 0). If the frontend ever emits code before the check,
the assertion fails instead of letting the function drop guest code.

**5.5 Code fetched in KLEE goes through the slow path.** D9 keeps code
fetches on `cpu_ld*_code_mmu()` in symbex builds. A later change that enables
the fast path for speed must first make `get_page_addr_code_hostp()` return a
`se_addend` pointer in multi-path builds, and must still keep pages with
`TLB_SYMB` on the slow path.

**5.6 Retranslation fires translation events again.** `tb_gen_code()` restarts
translation when the code is too large for one TB (`-2`), as the old code did,
and when taking the second page's lock would violate the lock order (`-3`).
The second case needs a second thread holding page locks and cannot happen in
libcpu, because `qemu_spin_trylock()` succeeds without contention (2.1). D6 handles
both anyway. It also restarts after a flush when the code
buffer fills up during code generation or `encode_search()`
(`goto buffer_overflow`), which D6 handles through the new `tcg_tb_alloc()`.
Every restart runs the frontend again and fires
the `onTranslate*` events again on a fresh `S2ETranslationBlock`. Plugins that
keep per-PC state at translation time already have to cope with the first
case.

**5.7 The deleted per-instruction breakpoint check changes TB shapes.** With
`check_for_breakpoints()`, a page that holds a breakpoint gets one-instruction
TBs. Plugins that work per TB see more TBs on such pages. Execution is
unchanged.

**5.8 `tb->flags` narrows to 32 bits.** Check every libs2ecore and plugin use
of `tb->flags` for a 64-bit mask (`grep -rn 'tb->flags'`). The uses found
while writing this plan test `HF_CPL_MASK`, `HF_CS32_SHIFT`, `HF_CS64_SHIFT`
and `VM_SHIFT`, which are all below bit 32.

**5.9 Range invalidation takes an inclusive end.** The old
`tb_invalidate_phys_page_range(start, end, is_cpu_write_access)` takes an
exclusive `end`. Upstream's `tb_invalidate_phys_range(cpu, start, last)`
takes the last byte. Five callers outside the replaced files use the old
function: `stl_phys_internal()` and `stw_phys_internal()` (`exec.c:309` and
`:343`), `cpu_physical_memory_rw()` and `cpu_host_memory_rw()`
(`exec-memdbg.c:114` and `:206`), and `breakpoint_invalidate()` in the
breakpoint half of `exec-bp.c` (`:40`). Each becomes
`tb_invalidate_phys_range(NULL, start, end - 1)`. The CPU argument is NULL
because none of them is a store from generated code, so there is no current
TB to stop. Passing `end` unchanged invalidates one byte past the range,
which can drop TBs on the next page when the range ends at a page boundary.

**5.10 KLEE notices an exit request one TB later.** The old
`fetch_and_run_tb()` tested `exit_request` after the lookup, so after any
translation, and just before running the TB. Upstream tests it in
`cpu_handle_interrupt()`, before the lookup, and relies on the check at the
start of each TB for requests that arrive later. `removeInterruptExit()`
deletes that check from LLVM TBs, so a request made during translation is
seen after the next TB that KLEE runs, not before it. Native TBs are not
affected.

**5.11 Most of upstream's logging is compiled out.** libtcg defines
`qemu_loglevel_mask(x)` as 0 (`tcg.h:94`). `log_cpu_exec()`, the "Stopped
execution of TB chain" line of `cpu_tb_exec()`, the `in_asm` block of
`translator_loop()` (and with it the frontend's `disas_log`) and the `out_asm`
block of `tb_gen_code()` therefore never print. `qemu_log_mask()` goes through
`libcpu_log_mask()`, so the "Linking TBs" line of `tb_add_jump()` does print.
Of the old loop's own lines, the loop entry and exit lines move to
`cpu_x86_exec()`, `fetch_and_run_tb` becomes `se_tb_exec` in
`cpu-exec-symbex.c.inc`, and `do_interrupt` stays in `cpu_handle_exception()`.
`setjmp entered` and `ltb` are deleted, and section 7 checks the result. Making `qemu_loglevel_mask()` test libcpu's mask would enable the
upstream lines, but also every other use in libtcg, which was not reviewed
*(unverified)*. It also requires that `CPU_LOG_TB_NOCHAIN` stays 0: upstream's
value (bit 13) is libcpu's `CPU_LOG_KVM_IO`, and `curr_cflags()` would then
disable chaining whenever `kvm_io` logging is on.

**5.12 The memory order value changes generated code.** In system mode,
libtcg's `tcg_gen_mb()` always emits the barrier (`tcg-op.c:229-240`), and
`tcg_gen_req_mo()` (`tcg-op-ldst.c:112`) asks for one unless the host's default
order already provides it. With today's `TCG_MO_ALL`, every guest load on an
x86_64 host emits a store-to-load barrier. Upstream's x86 value drops it,
which matches the x86 memory model. That changes the native code and the
LLVM functions (`INDEX_op_mb`, `tcg-llvm.cpp:1145`), and therefore
`LLVMInstructions`. Section 2.3 keeps `TCG_MO_ALL` for the switch so that
step 3 and step 4 can be compared with the baseline. The upstream value is a
separate change with its own measurement.

**5.13 The old decoder has no instruction length limit.** Its prefix loop
(`translate.c:4082`) accepts any number of prefixes, and nothing stops an
instruction at 15 bytes. An instruction that starts on the second page of a TB
can therefore extend into a third page. Upstream's `translator_ld()` asserts
that a read stays within two pages, so from step 4 on such a guest instruction
aborts libs2e instead of being translated. Whether a guest can actually reach
this, given the page limit of the translation loop, was not tested
*(unverified)*. The fix is the architectural limit: raise #GP after 15 bytes,
as upstream's decoder does, or end the TB before the instruction.


## 6. Steps

Each step ends with all six targets (`{i386,x86_64}` x `{plain, s2e, s2e_sp}`)
building in release and debug. Steps 1 and 2 change no behavior that the
testsuite can see.

### Step 1: Baseline (half a day)

On the current tree, on the same day:

- a full testsuite run;
- `stats.csv` of coreutils-echo and basic4-xmm: `LLVMInstructions`,
  `translatedBlocksCount`, `translatedBlocksLLVMCount`;

### Step 2: Preparation, with the old layer in place (4-6 days)

Each item is its own commit. After each commit, all six targets build in
release and debug and the testsuite passes. The items are in dependency
order. Where the order between two items is free, the simpler one comes
first.

1. **Exception numbers.** Move `EXCP_SE`, add `EXCP_YIELD`, `EXCP_ATOMIC` and
   `CPU_INTERRUPT_RESET` (2.2). This only changes headers. The
   `cpu_exec_reset` hook of item 9 uses `CPU_INTERRUPT_RESET`.
2. **Flushes from instruction handlers.** Switch the three `tb_flush()` calls
   of D7 in `WindowsMonitor.cpp` and `TBCoverageTracer.cpp` to
   `se_tb_safe_flush()`. Doing this before item 5 removes three call sites
   from the signature change.
3. **Range invalidation.** Convert the five callers of hazard 5.9 to
   `tb_invalidate_phys_range()` with an inclusive end, implemented over the old
   function until step 3 replaces it. The CPU argument replaces
   `is_cpu_write_access`: the old function gets a `CPUState *`, which is NULL
   for the five callers and the CPU of the store for
   `tb_invalidate_phys_page_fast()` (`exec-tb.c:467`). The SMC path then reads
   the CPU from that argument instead of `cpu_single_env`
   (`exec-tb.c:357`), which item 4 deletes.
4. **Dead code.** Remove the items listed at the end of section 1.1, the
   `ENABLE_RETRANSLATE` block in `s2e-kvm-io.cpp`, the `current_tb` assertions
   in libs2e and libs2ecore, the `current_tb` save and restore in
   `S2EExecutionState.cpp:119` and around `tb_phys_invalidate()` in
   `exec-tb.c`, and the `cpu_single_env` reads in `translate.c` (2.2).
   Two items of the list move to later commits because they have live
   callers: `cpu_resume_from_signal()` is replaced in item 5, and
   `cpu_set_debug_excp_handler()` in item 9. Removing the rest first means
   that item 5 does not convert functions that are about to be deleted.
5. **Upstream signatures.** `cpu_loop_exit()`, `cpu_loop_exit_restore()`,
   `cpu_restore_state()`, `cpu_exit()`, `tb_flush()` and
   `restore_state_to_opc()` take a `CPUState *` (and `const uint64_t *data`
   for the last). Add `cpu_loop_exit_noexc()` and use it in place of
   `cpu_resume_from_signal()`, then delete the latter. The callers are in
   libcpu, `CorePluginInterface.cpp`, `S2EExecutor.cpp`,
   `TBCoverageTracer.cpp`, `WindowsMonitor.cpp`, and in libs2e: `cpu_exit()`
   in `s2e-kvm-vcpu.cpp` (lines 690 and 1006, and the exit callback it gives
   to `LocalApic` at line 183) and in `s2e-kvm-io.cpp:194`. The names KLEE
   registers do not change. In the same commit, give `cpu_reset_interrupt()`,
   `cpu_interrupt()`, `cpu_abort()` and `cpu_dump_state()` their upstream
   signatures and rename the old `target_disas()` (2.2). `cpu_interrupt()`
   becomes a function, as upstream's, instead of a call through
   `cpu_interrupt_handler`. The handler pointer and its
   `__DEFINE_EXT_FUNCTION` go away, because the bitcode never referenced it. This change is
   mechanical but touches every component.
6. **The wrapper of 4.6**, around the old `cpu_exec()`. Rename the old
   function to `cpu_exec(CPUState *)` and delete the `cpu_exec` macro of 2.2,
   so that the wrapper alone carries the name `cpu_x86_exec`. The S12 test
   moves from the old loop into the wrapper. Needs item 5.
7. **Watchpoints.** Give `CPUWatchpoint` and the `BP_*` flags upstream's
   layout and values (2.2), and adapt the watchpoint insertion and removal in
   `exec-bp.c` and the old `cpu_check_watchpoint()` to them. The old check
   calls `cpu_interrupt()` and `cpu_loop_exit()`, so this comes after item 5.
8. **The exit mechanism.** Add `icount_decr` to `neg`. `cpu_exit()` sets
   `exit_request` and then the high half (2.2), the old loop clears the high
   half at the start of each iteration, and the
   old `gen_tb_start()` tests `icount_decr.u32 < 0` instead of `exit_request`.
   Replace `CF_HAS_INTERRUPT_EXIT` with its inverse, `CF_NOIRQ`, and give the
   `CF_*` flags upstream's values. This validates the new exit path, including
   `removeInterruptExit()`, before anything else moves. It changes generated
   code and the LLVM translator. It comes after item 5, so that `cpu_exit()`
   is written once with its final signature, and before item 10, so that the
   upstream header brings no change to the `CF_*` values.
9. **`TCGCPUOps`.** Create `target-i386/tcg-cpu.c` with the hooks of 2.3 except
   `translate_code`, and make the old `cpu-exec.c` call them instead of the
   functions they were written from. `debug_excp_handler` replaces
   `cpu_set_debug_excp_handler()`, which is deleted. After this, the switch
   replaces the code around the hooks, not the hooks. The hooks take upstream
   signatures (item 5) and `cpu_exec_reset` handles `CPU_INTERRUPT_RESET`
   (item 1). The old loop keeps its `cpu_loop_exit()` after `cpu_exec_reset`,
   because it has no path from the hook's return to `cpu_handle_exception()`.
   The hooks that nothing can call yet, `precise_smc` and
   `debug_check_breakpoint`, are set for step 3. `cpu_exec_enter` stays NULL
   (2.3), so the old loop does not call it. `tb-cpu-state.h` comes in its own
   commit before this item, as 2.1 requires.
10. **`TranslationBlock`.** Import `translation-block.h` into libtcg in two
    commits (2.1): the normalized upstream file, then the S2E block and the
    deletion of `tcg/tb.h`. `phys_hash_next` stays in the S2E block
    until step 3, because the old hash chains need it. Apply the type changes
    of 2.2 to the users, including the old `exec-tb.c`. Change
    `TCGContext.cpu` to a `CPUState *` (2.2). This item comes last because it
    touches the most code (libtcg, libcpu, libs2ecore and the plugins) and
    depends on an open question: whether the upstream header compiles as C++
    (10.3).

**Exit:** each commit builds on all six targets and passes the testsuite.

### Step 2b: Groundwork that shrinks the switch (3-4 days)

The review of step 2 found work that step 3 would otherwise do in one large
change and that does not need the new files. Each item is its own commit, in
this order. The tests come first so that they run on the old layer, which
separates existing bugs from regressions of the switch.

1. **The tests of the step 3 exit.** All of them are Linux guests, 32-bit and
   64-bit, and do not need a Windows image.
   - `basic13-smc`: a TB that overwrites its next instruction, a TB that
     overwrites an instruction on its second page, a store from outside the TB
     into the second page, an instruction that overwrites itself, and in 64-bit
     mode a chain of instructions that decode each other. Each case runs
     natively and in KLEE.
   - `basic14-hw-watchpoint`: a data breakpoint set through `ptrace()`, hit
     natively and in KLEE. This is the only test that reaches
     `cpu_check_watchpoint()` and its one-instruction TB.
   - `basic15-no-tb-flush`: a run that forks with
     `flush-tbs-on-state-switch` set to false.
   - `basic16-plugin-tb-flush`: `TBCoverageTracer` calls `se_tb_safe_flush()`
     from an instruction handler.
2. **Instruction count and `CF_NO_GOTO_TB`.** `cpu_gen_code()` takes the
   instruction count from `tb->cflags`. It used to overwrite the count with
   `TCG_MAX_INSNS`, so the one-instruction TB of `cpu_check_watchpoint()` was
   a full TB. `gen_goto_tb()` and `jmp_opt` test `CF_NO_GOTO_TB` (2.4), which
   no TB sets by accident since step 2 item 8. The watchpoint path sets it, so
   that the TB cannot chain past the check for `CPU_INTERRUPT_DEBUG`. The
   `tcg_debug_assert()` in `tcg_gen_goto_tb()` is not compiled in release or
   debug builds, so nothing else would catch a missing test.
   The old `cpu_check_watchpoint()` also aborted for a store in KLEE, which has
   no return address. It now finds the TB through the saved PC, as upstream's
   `tb_check_watchpoint()` does. `basic14-hw-watchpoint` found both bugs.
3. **`CPUState` and initialization.** Add `tcg_cflags`, `cflags_next_tb` and
   `singlestep_flags`, make `jmp_env` a `sigjmp_buf`, make `first_cpu` a
   `CPUState *` with a `CPU_FOREACH` that visits it, and add
   `CPUClass.get_pc` and `set_pc` (2.2). Create `src/s2e/tcg-init.c` with
   `tcg_exec_init()`, `tcg_exec_cpu_init()` and the `TCGContext` fields that
   are set once (2.1).
4. **`CPUJumpCache`.** Import `tb-jmp-cache.h` and `tb-hash.h`, in two commits
   as 2.1 requires. The jump cache moves to the heap, `cputlb.c` gets upstream's
   `tb_jmp_cache_clear_page()` back, and `tcg_flush_jmp_cache()` moves to
   `translate-all.c`, where upstream has it.
5. **`se_tb_exec()`.** Move the TB dispatch and `dump_regs()` of the old loop to
   `src/s2e/cpu-exec-symbex.c.inc` (D1). `g_sqi.exec.tb_exec()` returns
   `SE_TB_EXEC_DECLINED` when it needs an LLVM function, and `se_tb_exec()` sets
   `cflags_next_tb` back to `tb->cflags` in that case. The old lookup consumes
   the request when it generates a TB.
6. **`accel-deps.h`.** Rename `cputlb-deps.h`. The no-op `qemu_spin_*` macros
   stay only in the bitcode build. Native code uses the real functions of
   `utils/thread.h`, including for the TLB lock, whose type becomes upstream's
   `QemuSpin`. `tb_lock_page1()` therefore needs no `qemu_spin_trylock()` stub.
   `precise-pc.c` decodes the search data into `uint64_t`, as upstream does.

**Exit:** the same as step 2. The stall described in 10.3 must be understood
first, because it would look like a regression of these items.

### Step 3: The switch (5-8 days)

Import the files of 2.1 except `translator.c` and `translator.h`, which step 4
imports, and `tb-cpu-state.h`, which step 2 item 9 imported. The first
commit of the step adds all of them as `normalize.sh` emits them, together
with their `mapping.tsv` rows, and changes nothing else. The build ignores
them until the next commit. The commits after it apply the S2E deviations,
wire the files into the build and delete the old ones, so that every S2E
change to upstream text shows up as a diff against that first commit.

`translate_code` is a temporary adapter around the old
`gen_intermediate_code()`: it passes `*max_insns` to the old function, and then
does what `translator_ld()` will do in step 4. The count is an argument, so
`tb->cflags` never changes during translation. Upstream compares `tb->cflags`
with the `cflags` of each lookup, so a TB that was restarted with half the count
(-2) and kept a changed count in `cflags` would never be found, and would be
translated again on every execution. When the TB crosses a page, it looks up the second page with
`get_page_addr_code()`, records it with `tb_set_page_addr1()` and locks it with
`tb_lock_page1()`. When `get_page_addr_code()` returns -1 (the second page is
not RAM), it unlocks the first page and sets the first page address to -1 as
`translator_ld()` does, so that `tb_gen_code()` returns the TB without caching
it. Otherwise a TB that ends in device memory would be cached, and nothing
would invalidate it when that memory changes. The adapter is deleted in step 4.

Bring the targets up in this order:

1. **`{i386,x86_64}-softmmu`.** D4 (the stale-chaining half), the remaining
   changes of 2.1 to `accel-deps.h`, the log lines kept from the old loop
   (hazard 5.11), the move of the `precise-pc.h` declarations to `cpu/tb.h`,
   and the upstream SMC path (decision 4.1). Delete
   `tcg_target_force_tb_exit()` from libtcg and the aborting
   `helper_lookup_tb_ptr()` in `helper.c`, which `cpu-exec.c` now defines.
2. **`-s2e_sp-softmmu`.** D1, D2, D4 (the deferred flush), D5, D6, D7, D8,
   the rest of `cpu-exec-symbex.c.inc`, and `translate-all-symbex.c.inc`. Update the
   `__DEFINE_EXT_FUNCTION` list (hazard 5.3).
3. **`-s2e-softmmu`.** D3 and the LLVM half of D6.

**Exit:** a guest boots on all six targets, and the testsuite passes. These
tests of step 2b target the code of this step:

- `basic13-smc`: decision 4.1, D8 and the adapter;
- `basic14-hw-watchpoint`: `cflags_next_tb`, the declined TB of D1 and
  `watchpoint.c`, where upstream's `tb_check_watchpoint()` handles a store
  without a return address;
- `basic15-no-tb-flush`: D3 and D6;
- `basic16-plugin-tb-flush`: D4.

### Step 4: The frontend on `translator_loop()` (4-6 days)

Import `translator.c` and `translator.h`, again as one commit of normalized
upstream text followed by D9 and D10 in their own commit. Convert
`translate.c` as described in 2.4, delete the adapter, and set `CF_NO_GOTO_PTR`
in S2E builds (decision 4.4). The instruction length limit of hazard 5.13
goes in its own commit before the conversion.

**Exit:** the testsuite passes. `translatedBlocksCount` and `LLVMInstructions`
are within the run-to-run variation of master
(`softmmu-llvm-perf.md` gives about 15% for the latter). A guest that sets a
hardware breakpoint and single-steps over it (DR7, `TF`) behaves as before.

### Step 5: Cleanup (1-2 days)

- Delete the `TCGContext` fields that nothing reads any more: `env_ptr` and
  the TLB geometry (`PORTING.md` 3.3), and `exitreq_label` uses outside
  `translator.c`.
- Check that `merge.sh libcpu v11.1.0 v11.1.0` and
  `merge.sh libtcg v11.1.0 v11.1.0` resolve every new row, and that running
  `normalize.sh` again reproduces the import commits of steps 2 to 4 byte for
  byte.
- Update `PORTING.md`: phase 2 is done, phase 3 starts from a frontend that
  already implements `TranslatorOps`, and section 8 loses the two collisions
  this plan settles (`tb.h` and `precise-pc.c`).


## 7. Verification

- After step 2 and after each target of step 3, run the testsuite and compare
  with a master run from the same day, since timings between days differ by
  up to 30% (`softmmu-llvm-perf.md`).
- After steps 3 and 4, compare `LLVMInstructions` on coreutils-echo with the
  baseline. Check that the `module.bc` of the run contains the new code: the
  run uses the libraries in `install/share/libs2e`, not the build directory.
- Run with `LIBCPU_LOG_LEVEL=exec,int` once per step and check that the loop
  logs the lines chosen in step 3, interrupt deliveries and TB chaining (S15,
  hazard 5.11).
- In the S2E builds, run one symbolic test with the TLB audit enabled, since
  D3 and D8 invalidate TBs while the TLB holds KLEE references.


## 8. What this means for the frontend upgrade

The frontend upgrade (phase 3, then phase 5 for the instrumentation) inherits
these constraints:

- **`CF_PCREL` must stay off.** Upstream's x86 sets it for system emulation
  (`target/i386/cpu.c:10075`). A `CF_PCREL` TB does not store `tb->pc`, which
  libs2ecore and the plugins read, and the LLVM translator treats
  `insn_start`'s first argument as an absolute PC and stores it minus
  `cs_base` into `eip` (`tcg-llvm.cpp:1307`).
- **The S2E hooks move between equivalent callbacks.** After step 4, every
  `g_sqi.events` call of the old frontend sits in a `TranslatorOps` callback
  or in `disas_insn()`. The new frontend's `i386_tr_*` callbacks are the same
  slots. The instruction-shape hooks inside `disas_insn()` remain the hard part
  (`PORTING.md` phase 5).
- **The new decoder can rewind an instruction.** `i386_tr_translate_insn()`
  retranslates an instruction after a `siglongjmp()` and resets
  `base.insn_start` to `prev_insn_start`. Instrumentation emitted by
  `on_translate_instruction_start` for the abandoned attempt must not survive
  it.
- **Indirect jumps use `goto_ptr`** unless decision 4.4 still holds.
- **MMIO and `can_do_io`**: decision 4.3 still holds unless it was revisited.
- **Memory order**: `guest_default_memory_order` is still `TCG_MO_ALL` unless
  the change of hazard 5.12 was made.
- **Instruction length**: the new decoder enforces the 15-byte limit itself,
  so the limit added for hazard 5.13 goes away with the old decoder.


## 9. What this leaves alone

- The decoder, the helpers and their semantics. The frontend's entry point,
  its code fetches, its exit check, its breakpoint check, its use of
  `CF_NO_GOTO_TB` and the instruction length limit (hazard 5.13) change.
- The CPUID model, `NB_MMU_MODES` and the MMU index values.
- icount, record and replay, TCG plugins and MTTCG (multi-threaded TCG).
  They stay stubbed.
- The softmmu, the victim TLB and dynamic TLB sizing (`softmmu-update.md`
  section 8).
- The meaning of the S2E translation events: within one translation, they
  fire for the same instructions, in the same order, with the same arguments.
  What changes is how often a block is translated (hazard 5.6) and the shape
  of TBs on pages with breakpoints (hazard 5.7).

## 10. Working with this plan during implementation

The plan is a starting point, not a specification. The reviews found a new
set of problems each time, mostly where the new files meet libcpu: shims in
`accel-deps.h`, QEMU 1.0 signatures, fields that are never initialized, and
statements that some code "only matters" in a case libcpu does not have. More
of these will appear during implementation, and the steps make room for
them.

### 10.1 Checks at each step

Before the S2E commit of each imported file, and again before the exit of each
step:

- **Symbols.** For every function, macro and global that the new file defines
  or uses, find libcpu's, libtcg's and `accel-deps.h`'s definition, if any,
  and compare the signature. The compiler finds missing names. It does not find
  a macro that silently rewrites a definition, a no-op stub that should do
  something, or a stub that returns the wrong value.
- **Fields.** For every `CPUState`, `TranslationBlock` and `TCGContext` field
  that the new file reads, find where it is set and to what. Check the value
  at the first use, not only in steady state.
- **Claims.** For every statement of this plan that the step depends on,
  especially the ones that say something cannot happen or does not matter,
  check it against the code that will actually run, which is libcpu's and
  libtcg's. For example, an earlier revision said that
  `guest_default_memory_order` only matters with `CF_PARALLEL`, but
  `tcg_gen_mb()` always emits the barrier in system mode (hazard 5.12).
- **Bitcode.** After any change to `cputlb.c` or `op_helper.c`, list the
  undefined symbols of `op_helper.bc` (hazard 5.3).

### 10.2 When the code disagrees with the plan

- Fix the code, then correct the section of the plan that was wrong, in the
  same commit or the next one. The plan describes the code that landed, so
  that the next upgrade can rely on it.
- Record the change in 10.4 with the date and one line on what was wrong.
- New deviations take the next free number (D11, ...). A deviation that turns
  out unnecessary stays in section 3, marked as dropped with the reason, so
  that references to it stay valid.
- If a step needs more time than its estimate, or has to be split, change the
  step. The order of steps 2 to 4 matters (preparation with the old layer in
  place, then the switch, then the frontend), the content of each does not.
- A finding that is not understood yet is written down with *(unverified)*,
  not left out.

### 10.3 Open questions

These are known and left for implementation:

- Whether `qemu_loglevel_mask()` should test libcpu's mask (hazard 5.11).
- The checks of step 3 that were not done when it was committed: the debug
  builds, the full testsuite, the comparison of `LLVMInstructions` with the
  baseline, the `exec,int` log check and the TLB audit run of section 7. The
  release builds of all six targets compile. `basic0-singlepath`,
  `basic1-twopaths` and `basic13` to `basic16` passed, apart from the stall in
  the next item.
- Why some symbolic Windows runs slow down until they time out. One state
  spends its time in KLEE's expression simplifier (`Expr::compare()` under
  `BitfieldSimplifier`). `basic7-instmon` did this once before step 2, on
  2026-10-17, and six tests did it in the first full run after step 2, on
  2026-11-01. Whether step 2 made it more frequent is *(unverified)*. On the
  step 3 build, `windows64-basic1-twopaths` on `windows-7sp1ent-x86_64` did it
  once in a parallel run of 26 targets. After the fork, state 1 stopped
  translating new TBs and KLEE kept running a loop in a kernel driver at
  `0xfffff880_0133xxxx`. Five sequential reruns of that target passed in 48
  seconds each. The same runs were not repeated on the step 2b build, so whether
  step 3 changes the frequency is *(unverified)*.
- Whether a guest can reach the third-page assertion of hazard 5.13.
- When to adopt upstream's memory order value (hazard 5.12).

### 10.4 Changes during implementation

- 2026-10-31: step 2 reordered by dependency, then by size. Range
  invalidation now also replaces `cpu_single_env` in the SMC path, which the
  dead code removal depends on. TB traces are no longer part of the
  baseline or of any exit criterion. Steps are judged on correct execution
  (the testsuite), not on TB-for-TB equality with the old layer.
- 2026-10-31: step 2 item 5 also removes `cpu_interrupt_handler`, which the
  plan did not mention.
- 2026-11-01: step 2 item 8 erases the dead `icount_decr` load in
  `removeInterruptExit()` instead of relying on the optimizer (hazard 5.4),
  and removes `CF_NOCACHE`, which nothing sets and upstream does not have.
- 2026-11-01: step 2 item 9 imports `tb-cpu-state.h`, which the plan left for
  step 3 although the `get_tb_cpu_state` hook returns its type. The item also
  drops the `cpu_get_tb_cpu_state()` call in the SMC path of `exec-tb.c`, whose
  results nothing read.
- 2026-11-01: step 2 item 10 moves `vaddr.h` from libcpu to libtcg, which the
  new header needs, and defines `ram_addr_t` in `tcg/tb-s2e.h`. `jmp_lock`
  moves to `QemuSpin` in its own commit, which also deletes `tb_lock`, unused,
  and `utils/spinlock.h`, whose last user was `jmp_lock`.
- 2026-11-01: added step 2b, from the review of step 2. Section 2.4 said that
  debug builds abort when a breakpoint page holds a direct jump, but the
  assertion is not compiled in any build. D1 now reports a declined TB with
  `SE_TB_EXEC_DECLINED`. D8 now states what `se_current_tb` holds in a resumed
  state, which was an open question. The TLB lock is real in native code, where
  the plan had a no-op with a `qemu_spin_trylock()` stub.
- 2026-11-01: step 3 added D11 and D12, which the plan missed: `cpu_interrupt()`
  does not stop a chain of TBs, and `cpu_exec_exit()` can longjmp. It also imports
  `cpu-loop.h`. The adapter passes the instruction count as an argument, because
  a save and restore of `tb->cflags` would save the changed count when the
  frontend itself longjmps with -2. Step 3 said that step 2 item 9 imported
  `translator.c` and `translator.h`, but step 4 imports them. `watchpoint.c` is
  not imported unmodified (D11).
