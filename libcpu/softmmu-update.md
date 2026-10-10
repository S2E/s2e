# Replacing the softmmu headers with QEMU 11.1's `cputlb.c`

The softmmu is the code that turns a guest virtual address into a host access:
the TLB, its fill and flush functions, and the load and store helpers that
generated code and C helpers call when the inline fast path does not apply.
libcpu still has the QEMU 1.0 version, spread over four template headers and
`exec-tlb.c`. This document is the plan for replacing it with upstream's
`accel/tcg/cputlb.c` at `v11.1.0`.

`PORTING.md` schedules this inside phase 2, together with the rest of
`accel/tcg`, and defers the symbolic half to phase 6. This plan changes that
order: the softmmu is ported alone, on the current tree, with symbolic execution
kept working throughout. The reasoning is the same as for `tlb-update.md`. The
softmmu is the part of `accel/tcg` most entangled with S2E, so it is easier to
validate on a tree that still boots than in the middle of the larger import.

**Status: implemented, not validated.** Steps 1 to 4 are in the tree and all
six targets build. No guest has been booted on it yet, so the exit criteria of
step 3 are still open. The code differs from the plan below in the following
places. Where the two disagree, the code is the reference.

- **Memory model (deviation 1).** `cputlb.c` keeps upstream's text for the
  memory API. `cpu/memory.h` defines a small `MemoryRegion` and
  `MemoryRegionSection` over `MemoryDesc`, and `src/s2e/cputlb-deps.h`
  implements `address_space_translate_for_iotlb()` and the
  `memory_region_*()` functions on top of them. `CPUTLBEntryFull` keeps its
  `section` field. This replaces the plan's `mem_desc` field and
  `mem-shim.h`, and removes deviation 1.
  The MMIO functions of the shim convert between the byte order that the
  softmmu asks for and the little-endian values of the device interface, as
  upstream's memory API does: the softmmu reads devices in big-endian order.
  They also split an 8-byte access into two 4-byte ones, which is the largest
  size that libs2e's device interface takes.
- **One glue header.** `src/s2e/cputlb-deps.h` holds every stub and shim.
  `internal-common.h` and `backend-ldst.h` are not imported: the first
  mostly declares code that is not ported, and the second reduces to an
  empty `cpu_req_mo()` for an x86 guest on an x86 host.
- **`cpu->cc->tcg_ops`.** `CPUState` has a `cc` pointer to a `CPUClass` that
  only contains `tcg_ops`, so upstream's expression compiles unchanged.
  `CPUState` also gained `created` and `ignore_memory_transaction_failures`,
  and `neg` gained `can_do_io`, for the same reason.
- **Watchpoints (hazard 5.7).** `watchpoint.c` is not imported.
  `cpu_watchpoint_address_matches()` and `cpu_check_watchpoint()` are
  written in `exec-bp.c` over the QEMU 1.0 watchpoint list.
- **`*_all_cpus_synced` flushes.** They are not pruned. The work queue
  functions they call run the work in place.
- **Victim TLB (deviation 3).** `victim_tlb_hit()` is not edited. The
  eviction is skipped, so the victim table stays empty and the function
  never finds anything. The bitcode build replaces it with `false`.
- **Memory tracing (deviation 6).** `do_{ld,st}{1,2,4,8}_mmu()` are not
  edited. `src/s2e/cputlb-symbex-ldst.c.inc` wraps them and redirects their
  callers with macros. The wrappers no longer set `MEM_TRACE_FLAG_IO`.
- **`se_mmu_resolve()` keeps no state and writes nothing.** The plan's
  scratch buffer and its write of zeros before a store are gone. When
  natively executed code cannot access a RAM page directly,
  `se_mmu_resolve()` sets `TLB_MMIO` in the flags of the lookup result, which
  is a local copy. The upstream load and store code then calls
  `do_ld_mmio_beN()` or `do_st_mmio_leN()`, with the value for a store. Each
  starts with a call to `se_ram_ld_beN()` or `se_ram_st_leN()`, which does
  the one real access through libs2ecore when the page is RAM.
  `se_mmu_resolve()` checks both pages for a reason to switch to symbolic
  execution before it decides anything else.
- **No global variables in the S2E softmmu code.** The bitcode build has no
  ops table: `SE_TCG_HAS_OP()` answers for it. The memory trace wrapper
  reads the TLB flags again to decide whether to report an access to
  symbolic hardware.
- **Hazard 5.3.** `required_atomicity()` is not redirected. `cputlb.c` only
  reaches it through `load_atom_N()` and `store_atom_N()`, which are. The
  16-byte entry points stay in the bitcode build.
- **Bitcode build.** Five `#ifndef SYMBEX_LLVM_LIB` regions remove the
  native-only code, and `SE_TCG_OPS()` / `SE_TCG_OP()` select the bitcode
  copies of the target hooks.
- **TB invalidation.** `tb_invalidate_phys_page_fast()` only handles stores
  that stay inside 8 aligned bytes. The old softmmu only called it for
  aligned accesses. The shim splits a store where it crosses a multiple
  of 8.
- **`flush_tlb_cache_mmuidx()`.** libcpu clears `object_state` of the full
  entries itself, in `se_tlb_drop_mmuidx()`. The libs2ecore hook only drops
  the map references.
- **Step 4.** The static translator code was dead and has been removed
  (`tools/include/Translator/` and every `STATIC_TRANSLATOR` conditional).
  The `ld*_raw_symb` accessors in `cpu-all.h` are still there, unused.
  `PORTING.md` and `tlb-update.md` have not been updated yet.


## 1. The softmmu today

| File | Lines | Role |
|---|---:|---|
| `src/softmmu_template.h` | 664 | Slow path: `helper_{ld,st}*`, `slow_{ld,st}*`, `io_{read,write}*` and their `_chk` wrappers |
| `src/softmmu_header.h` | 346 | Inline accessors with their own TLB lookup: `cpu_ld*_kernel`, `_user`, `_data`, `_code` |
| `src/softmmu_exec.h` | 152 | Instantiates the header per MMU mode; defines the `ldl(p)` shorthand macros |
| `include/cpu/softmmu_defs.h` | 125 | Prototypes for all of the above |
| `src/exec-tlb.{c,h}` | 381 | `tlb_flush`, `tlb_flush_page`, `tlb_set_page`, dirty tracking in the TLB |
| `src/exec.c` (part) | ~170 | The notdirty, DMA and watchpoint `MemoryDescOps`, and `get_page_addr_code()` |

The template is instantiated in three places:

- `target-i386/op_helper.c`, suffix `_mmu`: the data helpers.
- `target-i386/op_helper.c`, suffix `_mmu_symb`, in the native symbex build
  only. Generated code calls this copy under `CONFIG_SYMBEX_MP`
  (`translate-all.c` installs it in `TCGContext::qemu_ld_helpers`).
- `exec.c`, suffix `_cmmu`: code fetches.

The same source runs in three different ways:

**Native, from generated code.** libtcg's backend inlines the TLB lookup and, on
a hit, loads through `se_addend`. This field points into the concrete buffer of
the KLEE object that backs the page in the current state. A page that holds
symbolic data has `TLB_SYMB` set in its comparators, so the inline compare
fails and the helper runs. The helper treats any flag bit as "IO access" and
calls `io_read`, which checks whether the bytes being read are concrete
(`_se_check_concrete`). If they are, it loads through `se_addend`. If they are
not, it calls `g_sqi.exec.switch_to_symbolic(retaddr)`, which does not return:
the instruction is executed again by KLEE.

**Native, from a C helper.** The accessor has no return address into generated
code, so it cannot switch to symbolic mode: a helper that has already modified
the CPU state cannot be rolled back. It reads through the `ld*_raw` accessors
instead, which concretize the data (`g_sqi.mem.read_ram_concrete`).

**As LLVM bitcode, inside KLEE.** `op_helper.c` is also compiled with
`SYMBEX_LLVM_LIB` into `op_helper.bc`. In that build the template calls
`tcg_llvm_fork_and_concretize()` on the address. With
`fork-on-symbolic-address` disabled, only the page number is made concrete and
the offset inside the page stays symbolic. The TLB lookup then runs as bitcode
on the registered TLB object, and the final access at `addr + addend` goes
through the KLEE address space, which handles symbolic data and copy-on-write.
libs2ecore replaces some of the bitcode functions with native C++ handlers
(`MMUFunctionHandlers.cpp`): `helper_{ld,st}{b,w,l,q}_mmu` and
`cpu_{ld,st}*_kernel`. These handlers make the whole address concrete.

Three S2E flags share the comparator with QEMU's:

| Flag | Meaning | Effect |
|---|---|---|
| `TLB_SYMB` | The page holds symbolic data | Loads and stores leave the inline path |
| `TLB_NOT_OURS` | The KLEE object backing the page is shared with another state | Stores leave the inline path so that the object is copied first |
| `TLB_MEM_TRACE` | A plugin subscribed to memory access events | Every access reaches the helper, which reports it |

Pages that contain symbolic MMIO or DMA ranges are marked through QEMU's own
flags: `tlb_set_page()` sets `TLB_NOTDIRTY` on the read comparator and
`TLB_MMIO` on the write comparator when `g_sqi.mem.is_mmio_symbolic()` is true.


## 2. Target shape

### 2.1 Files, and which library owns them

The libraries form a chain: libutils, then libtcg, then libcpu, then
libs2ecore. A library includes headers only from the ones before it. libtcg
includes no `cpu/` header today, and this work keeps it that way.

The rule for a new file follows from the chain. A file belongs to libtcg only
if the code generator needs it to compile. Everything that implements a
memory access, or that needs `CPUState`, belongs to libcpu. Upstream's `tcg/`
directory follows the same line: of the TLB headers, it includes only
`exec/tlb-common.h`.

**libtcg.** One new header. The other files that the code generator shares
with the softmmu are already there and already at `v11.1.0`.

| File | From upstream | Note |
|---|---|---|
| `include/tcg/exec/tlb-common.h` | `include/exec/tlb-common.h` | New. `CPUTLBEntry` and `CPUTLBDescFast`, which the backend reads with `offsetof()`. Carries `se_addend` (2.2). Replaces the structure half of `tcg/tlb.h`. |
| `include/tcg/tcg-memopidx.h` | `include/exec/memopidx.h` | Present, updated in step 2 (hazard 5.8) |
| `include/tcg/tcg-memop.h`, `tcg-ldst.h` | `include/exec/memop.h`, `include/tcg/tcg-ldst.h` | Present. `tcg-ldst.h` declares `helper_{ld,st}*_mmu`. |
| `include/tcg/accel/tcg-runtime.h`, `getpc.h`, `exec/helper-proto-common.h` | same names | Present. `tcg-runtime.h` declares the atomic and 128-bit helpers. |

**libcpu.**

| File | From upstream | Note |
|---|---|---|
| `src/accel/cputlb.c` | `accel/tcg/cputlb.c` | The deviations of section 4 |
| `src/accel/ldst_common.c.inc` | `accel/tcg/ldst_common.c.inc` | `helper_*_mmu`, `cpu_*_mmu`, `helper_{ld,st}_i128` |
| `src/accel/ldst_atomicity.c.inc` | `accel/tcg/ldst_atomicity.c.inc` | See hazard 5.3 |
| `src/accel/atomic_common.c.inc`, `atomic_template.h` | same | Moved from `libtcg/src/`, together with their two `mapping.tsv` rows, and restored to upstream's text. Compiled, but not called before the phase 3 frontend. |
| `src/accel/tlb-bounds.h`, `backend-ldst.h`, `internal-common.h` | same | `tlb-bounds.h` carries the pinned size |
| `src/accel/watchpoint.c` | `accel/tcg/watchpoint.c` | Replaces the watchpoint half of `exec-bp.c` |
| `src/s2e/cputlb-symbex.c.inc` | none, S2E file | `se_mmu_resolve()` and the libs2ecore accessors (2.4); not in `mapping.tsv` |
| `include/cpu/accel/cpu-ldst.h`, `cpu-ldst-common.h`, `cpu-ops.h`, `cpu-mmu-index.h`, `probe.h` | `include/accel/tcg/` | The public accessor API and `TCGCPUOps` |
| `include/cpu/exec/cputlb.h`, `tlb-flags.h`, `vaddr.h`, `memattrs.h`, `mmu-access-type.h`, `page-protection.h` | `include/exec/` | `tlb-flags.h` replaces the flag half of `tcg/tlb.h`. libtcg uses none of the flags. |

Each new row goes into the `mapping.tsv` of its library with `BASELINE` =
`v11.1.0`.

`include/exec/target_page.h` is not imported. `TARGET_PAGE_BITS` and the two
macros derived from it are already defined in `tcg/tcg.h` and in libcpu, and
`cputlb.c` uses those.

**Removed from libtcg.** These are softmmu definitions that libtcg carries
today and that the code generator does not use:

- `include/tcg/tlb.h`, split as described above.
- `src/atomic-helpers.c`. It instantiates the atomic templates with bodies
  that call `abort()` and defines stub `helper_{ld,st}_i128()`. `cputlb.c` now
  defines all of these symbols, so keeping the file would define them twice.
- `include/tcg/cpu.h`, which only defines the `PAGE_*` protection bits.
  `page-protection.h` replaces it. Of its three includers, only
  `libcpu/src/cpu-all.h` uses the bits.
- `CPU_TLB_BITS`, `CPU_TLB_SIZE` and `CPU_TLB_DYN_MAX_BITS` in `tcg/tcg.h`.
  `tlb-bounds.h` defines the bounds, and `translate-all.c` keeps passing the
  maximum to the backend through `TCGContext::tlb_dyn_max_bits`.

**Removed from libcpu.** The four `softmmu_*.h` files, `exec-tlb.{c,h}`, and
from `exec.c` the notdirty, DMA and watch `MemoryDescOps`,
`se_notdirty_mem_{read,write}`, `se_ismemfunc` and `get_page_addr_code()`.
`exec-phys.{c,h}` loses the notdirty and watch sections.

**Symbols that libtcg declares and libcpu defines.** The include graph has no
cycle, but generated code calls helpers whose implementation needs the TLB,
so libtcg refers to a few symbols that only libcpu can define:

| Symbol | Referenced from libtcg by | Defined in libcpu by |
|---|---|---|
| `helper_lookup_tb_ptr` | the helper table built from `tcg-runtime.h` | `cpu-exec.c` (already the case today) |
| `helper_atomic_*`, `helper_{ld,st}_i128` | the same table | `atomic_common.c.inc` and `ldst_common.c.inc`, through `cputlb.c` |
| `helper_{ld,st}*_mmu` | `qemu_{ld,st}_helpers[]` in `tcg.c` | `ldst_common.c.inc`, through `cputlb.c` |

This is the only upward reference, it exists today for the first row, and it
is how upstream is organized. The alternative for the third row is to keep
the S2E tables in `TCGContext`, which libcpu fills at startup. It would not
remove the first two rows, so it is not worth the backend deviation.

Two consequences follow. libs2e links `libcpu.a` before `libtcg.a`, and the
linker resolves libtcg's references only against objects it has already
taken from `libcpu.a`. `cputlb.o` is always taken, because libs2ecore and the
rest of libcpu call `tlb_flush()`, but the link line should wrap the two
archives in `--start-group` and `--end-group` so that this does not depend on
the order. A program that uses libtcg without libcpu must define the symbols
itself.

### 2.2 Data structures

`CPUTLBEntry` becomes upstream's union with one S2E field. It stays 64 bytes in
symbex builds and becomes 32 bytes otherwise:

```c
typedef union CPUTLBEntry {
    struct {
        uintptr_t addr_read;
        uintptr_t addr_write;
        uintptr_t addr_code;
        uintptr_t addend;
#ifdef CONFIG_SYMBEX
        /* Host address of the page in the current state's KLEE object, minus
           the guest address. The backend loads it on the inline path. */
        uintptr_t se_addend;
#endif
    };
    uintptr_t addr_idx[(1 << CPU_TLB_ENTRY_BITS) / sizeof(uintptr_t)];
} CPUTLBEntry;
```

`CPUTLBEntryFull` is upstream's, with two changes in `state.h`:

- `MemoryRegionSection *section` becomes `const MemoryDesc *mem_desc`, which is
  NULL for MMIO (`PORTING.md` decision 3.2).
- The target-specific `extra` union holds `void *object_state`, moved out of
  the fast entry. Only the slow path and libs2ecore read it. Upstream's flush
  functions do not touch `fulltlb[]`, so the libs2ecore flush hooks
  (deviation 5) set the field to NULL. `audit()` and `updateTlbEntry()` treat
  a non-NULL value as a live reference.

The flags are allocated as follows in `tlb-flags.h`:

| Flag | Where | Bit | Set by |
|---|---|---:|---|
| `TLB_SYMB` | comparator, in `TLB_FLAGS_MASK` | 9 | libs2ecore, on all three comparators |
| `TLB_NOT_OURS` | comparator, in `TLB_FLAGS_MASK` | 10 | libs2ecore, on `addr_write` |
| `TLB_MEM_TRACE` | comparator, in `TLB_FLAGS_MASK` | 11 | `tlb_set_page_full()`, on `addr_read` and `addr_write` |
| `TLB_SYMB_MMIO` | `slow_flags[]`, in `TLB_SLOW_FLAGS_MASK` | 5 | `tlb_set_page_full()`, on loads and stores (section 7) |

`slow_flags[]` cannot hold the first three. `mmu_lookup1()` and
`probe_access_internal()` merge the comparator flags and the slow flags into
one `int`, where bit 6 is `TLB_INVALID_MASK`, bit 7 is `TLB_NOTDIRTY` and bit 8
is `TLB_FORCE_SLOW`. Only bit 5 is free in that merged value. Bits 9 to 11 are
free in the comparator because `TARGET_PAGE_BITS` is 12 on x86; add a
build-time assertion that `TLB_FLAGS_MASK` stays below `TARGET_PAGE_SIZE`.

Keeping the three dynamic flags in the comparator has two advantages.
libs2ecore sets and clears one bit, as it does today, and has no
`TLB_FORCE_SLOW` bit to keep consistent. `tlb_set_compare()`, `mmu_lookup1()`
and `probe_access_internal()` already propagate every bit of `TLB_FLAGS_MASK`,
so they need no edit. Any nonzero bit below the page mask makes the backend's
inline compare fail, so no backend change is needed either.

`TLB_SYMB_MMIO` is set once, when the entry is filled. `tlb_set_compare()`
adds `TLB_FORCE_SLOW` for it like for any other slow flag.

`CPUTLB` in `state.h` becomes upstream's (`CPUTLBCommon c`, `d[]`, `f[]`), with
the storage for `f[i].table` and `d[i].fulltlb` allocated statically inside
`CPUNegativeOffsetState`. The bitcode softmmu reads both arrays, so both must
lie inside the KLEE object that libs2ecore registers once over `neg`. This is
the pinned-size option of `tlb-update.md` section 5. The victim TLB is disabled
(`PORTING.md` 9.4).

`NB_MMU_MODES` stays 2 and `cpu_mmu_index()` keeps its two values until the
phase 3 frontend arrives. `cputlb.c` does not depend on the number.

### 2.3 Entry points

| Caller | Today | After |
|---|---|---|
| Generated code | `tcg_helper_ld{b,w,l,q}_mmu[_symb]`, `helper_st*_mmu[_symb]`, taken from `TCGContext::qemu_{ld,st}_helpers` | `helper_ld{ub,uw,ul,q,sb,sw,sl}_mmu`, `helper_st{b,w,l,q}_mmu`, called directly by the backend as upstream does |
| C helpers | `cpu_ld*_{kernel,user,data}`, `ldl(p)` macros | `cpu_ld*_mmuidx_ra()` and `cpu_ld*_data_ra()`, inline wrappers around `cpu_{ld,st}{b,w,l,q}_mmu()` |
| Translator | `cpu_ld*_code` | `cpu_ld{b,w,l,q}_code_mmu()` |
| Code generated by `tcg-llvm.cpp` | `helper_ld{b,w,l,q}_mmu(env, addr, mmu_idx, retaddr)` | `helper_ld*_mmu(env, addr, oi, retaddr)`; loads return `tcg_target_ulong` and must be truncated |

The arguments change from `(env, addr, mmu_idx, retaddr)` to
`(env, addr, oi, retaddr)`, where `oi` (a `MemOpIdx`) packs the access size,
alignment and MMU index. libtcg already passes `oi`; the old helpers only work
because they extract the MMU index from it (hazard 5.8). The S2E override tables in `TCGContext`
and `translate-all.c` are deleted, and `tcg_out_qemu_{ld,st}_slow_path()` in
the backend returns to upstream's text.

`op_helper.c` and the old `translate.c` are replaced in phase 3, so their ~250
call sites are not edited. A compatibility header, `src/softmmu-compat.h`, maps
the old names onto the new API:

```c
#define cpu_ldl_kernel(env, p) cpu_ldl_mmuidx_ra(env, p, 0 /* kernel mode */, 0)
#define ldl(p)                 cpu_ldl_data_ra(env, p, 0)
#define cpu_ldub_code(env, p)  cpu_ldb_code_mmu(env, p, make_memop_idx(MO_UB, cpu_mmu_index(env)), 0)
```

A return address of 0 matches the `NULL` that the old inline accessors pass.
The header is deleted with `op_helper.c`.

### 2.4 Native and bitcode builds of the same file

`cputlb.c` is compiled twice, as `op_helper.c` is today: natively into
`libcpu.a`, and with `-DSYMBEX_LLVM_LIB` into bitcode that is linked into
`op_helper.bc`. Symbolic addresses keep working because the lookup and the
final access run as bitcode.

The bitcode build keeps the access path and turns everything else into calls to
the native copy:

| Runs as bitcode | Stays native, called from bitcode |
|---|---|
| `helper_{ld,st}*_mmu`, `cpu_{ld,st}*_mmu`, `cpu_ld*_code_mmu` | `tlb_set_page*()`, reached through `cpu_x86_handle_mmu_fault()` |
| `do_ld{1,2,4,8}_mmu`, `do_st{1,2,4,8}_mmu` | `notdirty_write()` |
| `mmu_lookup()`, `mmu_lookup1()`, `mmu_watch_or_dirty()` | `do_ld_mmio_beN()`, `do_st_mmio_leN()` |
| `do_ld_{1,2,4,8}`, `do_st_{1,2,4,8}`, the `beN` / `leN` cross-page loops | `cpu_check_watchpoint()` |
| `tlb_fill_align()` and the x86 `TCGCPUOps` hooks | all flush functions, `probe_access*()` |

`tlb_fill_align()` and `x86_cpu_tlb_fill()` run as bitcode because the fault
address can have a symbolic offset. The old `tlb_fill()` handles this by
passing the concrete page address to `cpu_x86_handle_mmu_fault()` and then
writing the full address to CR2 (or to the VMCB) and to the `on_page_fault`
event. `x86_cpu_tlb_fill()` does the same: it masks the address before the
native call and restores the full fault address afterwards. A native hook
would either receive only the page address, and report a page-aligned CR2, or
receive the symbolic address, and fork on its value (hazard 5.4).

The native-only functions are `static` upstream. A macro, `SE_NATIVE`, replaces
`static` on the definitions of `notdirty_write()`, `do_ld_mmio_beN()` and
`do_st_mmio_leN()`. It expands to `static` when `CONFIG_SYMBEX` is off and to
nothing in symbex builds, which exports the function. Their bodies sit inside
`#ifndef SYMBEX_LLVM_LIB`, so the bitcode build sees only the prototypes.
libs2ecore lists these functions with `__DEFINE_EXT_FUNCTION`, as it lists
`io_readb_mmu` and `se_notdirty_mem_write` today. The flush functions,
`tlb_set_page*()` and `probe_access*()` are already public; the bitcode build
leaves their bodies out the same way.

The S2E cases are resolved in one place, so that `do_ld_*` and `do_st_*` keep
upstream's text. `mmu_lookup()` calls `se_mmu_resolve()` for each page after
`mmu_watch_or_dirty()`, when the page carries one of the S2E flags or
`TLB_MMIO`. The function lives in an S2E file, `src/s2e/cputlb-symbex.c.inc`,
which `cputlb.c` includes after `ldst_atomicity.c.inc` (hazard 5.3). When it
returns, each page is either accessed directly at `haddr` or routed to the
MMIO functions, which do the access through libs2ecore. A watchpoint hit or a fault leaves `mmu_lookup()`
before `se_mmu_resolve()` runs, so the function never acts on an access that
does not happen.

How each case is handled in the two builds:

| Case | Native build | Bitcode build |
|---|---|---|
| Address | Always concrete | `mmu_lookup()` calls `tcg_llvm_before_memory_access()`, then `tcg_llvm_fork_and_concretize()` on the address when `fork-on-symbolic-address` is set. `tlb_index()` concretizes the page number and computes the index from the result (hazard 5.5). |
| Host address | `mmu_lookup1()` computes `addr + se_addend` under `CONFIG_SYMBEX_MP`, else `addr + addend` | `addr + addend`; the access resolves through the KLEE address space |
| `TLB_SYMB`, loads | `se_mmu_resolve()` checks the accessed bytes with `_se_check_concrete()`. If they are symbolic and `ra` is in generated code, it calls `switch_to_symbolic(ra)`. Otherwise it routes the load to `do_ld_mmio_beN()`, which reads the concretized bytes with `g_sqi.mem.read_ram_concrete()`. | Ignored |
| `TLB_SYMB` or `TLB_NOT_OURS`, stores | If the object is shared or the accessed bytes are symbolic, `se_mmu_resolve()` routes the store to `do_st_mmio_leN()`, which writes the value with `g_sqi.mem.write_ram_concrete()`. This copies the object, makes the bytes concrete and updates the TLB entry. | Ignored; KLEE copies the object |
| `TLB_MEM_TRACE` | `g_sqi.events.after_memory_access()` in `do_{ld,st}{1,2,4,8}_mmu`, except for code fetches | `tcg_llvm_after_memory_access()` at the same sites |
| `TLB_NOTDIRTY` (stores) | `notdirty_write()` | Calls the native `notdirty_write()`, then stores |
| `TLB_MMIO` and `TLB_SYMB_MMIO` | `se_mmu_resolve()` calls `switch_to_symbolic(ra)` if `g_sqi.mem.is_mmio_symbolic()` is true and `ra` is in generated code, as `io_read` does today. Otherwise `do_{ld,st}_mmio_*()` dispatch through `MemoryDescOps` for `TLB_MMIO`, and a `TLB_SYMB_MMIO` page is accessed as RAM. | `TLB_MMIO` calls the native function. Both flags then call `tcg_llvm_trace_mmio_access()` next to the memory trace call. |
| TLB miss | `tlb_fill_align()` | `tlb_fill_align()` as bitcode, calling the bitcode `x86_cpu_tlb_fill()` by name |

The S2E code works with three addresses, and they must not be mixed up.
`haddr` is based on `se_addend` and is only valid for a direct access.
`g_sqi.mem.read_ram_concrete()` and `write_ram_concrete()` take the host RAM
address, `addr + entry->addend`, which is the address KLEE binds the object
at. `g_sqi.mem.is_mmio_symbolic()` takes the guest physical address,
`full->phys_addr` plus the page offset. The old `io_read` passes it the
virtual address.

The native handlers in `MMUFunctionHandlers.cpp` stay for the
`helper_{ld,st}*_mmu` entry points, which is where code translated by
`tcg-llvm.cpp` enters. They are rewritten against the new TLB layout and the
new arguments. The `cpu_{ld,st}*_kernel` handlers are removed: upstream has no
per-mode accessor functions, so kernel-mode accesses from helpers run through
the bitcode `cpu_*_mmu` functions like all others.


## 3. What `cputlb.c` needs from code that is not ported yet

| Dependency | Upstream provider | Bridge |
|---|---|---|
| `cpu->cc->tcg_ops->{tlb_fill, mmu_index, pointer_wrap, do_unaligned_access}` | `target/i386/tcg/tcg-cpu.c` | `cpu->tcg_ops` (already in `state.h`). The four hooks are written in `target-i386/op_helper.c`, which is compiled both natively and as bitcode (2.4), over the old `cpu_x86_handle_mmu_fault()` and `raise_exception_err_ra()`. The old `tlb_fill()`, including its `on_tlb_miss` and `on_page_fault` events and its CR2 handling, becomes `x86_cpu_tlb_fill()`. |
| `MemoryRegionSection`, `address_space_translate_for_iotlb()`, `memory_region_dispatch_{read,write}()` | `system/memory.c` | `src/s2e/mem-shim.h` over `mem_desc_find()` and `MemoryDescOps` (`PORTING.md` 3.2). About eight sites in `cputlb.c`. |
| `physical_memory_is_clean()`, `_get_dirty_flag()`, `_set_dirty_range()`, `_test_and_clear_dirty()`, `qemu_ram_addr_from_host_nofail()` | `system/physmem.c` | Same shim, over the byte-per-page mask of `exec-ram.h`. `_test_and_clear_dirty()` must call `tlb_reset_dirty()` with the host address range, as upstream's does. `tlb_protect_code()` relies on that call to set `TLB_NOTDIRTY` on the entries that map the page. |
| `tb_invalidate_phys_range_fast()` | `tb-maint.c` | Wrapper around the old `tb_invalidate_phys_page_fast()` in `exec-tb.c` |
| `tb_jmp_cache_clear_page()` uses `CPUJumpCache` | `tb-jmp-cache.h` | Temporary deviation: call the old `tlb_flush_jmp_cache()` over `neg.tb_jmp_cache[]`. Removed when `cpu-exec.c` is imported. |
| `tcg_flush_jmp_cache()`, called by the full and range flushes | `translate-all.c` | Stub header: clear `neg.tb_jmp_cache[]`, as the old `tlb_flush()` does |
| `cpu_in_serial_context()` in `ldst_atomicity.c.inc` | `internal-common.h` | Stub header: always true. There is one vCPU, so `required_atomicity()` never asks for more than byte atomicity. |
| `get_page_addr_code_hostp()` returns -1 for MMIO | `cputlb.c` itself | The two old callers (`cpu-exec.c`, `exec-tb.c`) call `cpu_abort()` on -1, as `get_page_addr_code()` does today. Deviation 10 keeps a RAM page that carries S2E flags from being reported as MMIO. |
| `cpu_watchpoint_address_matches()`, `cpu_check_watchpoint()` | `accel/tcg/watchpoint.c` | Imported in this work. The breakpoint half of `exec-bp.c` stays. |
| `bql_lock()`, `cpu_io_recompile()`, `can_do_io`, plugin memory callbacks, trace points, `assert_cpu_is_self()` | various | Stub headers: no-ops, with `can_do_io` always true |
| `async_safe_run_on_cpu()` in the `*_all_cpus_synced` flushes | `cpu-common.c` | Pruned; there is one vCPU and x86 does not call them |


## 4. S2E deviations in the imported files

Each one gets a comment that states why, so that the next merge can keep it.

1. **Memory model.** `tlb_set_page_full()`, `io_prepare()`, `io_failed()`,
   `int_ld_mmio_beN()` and `int_st_mmio_leN()` use `MemoryDesc`.
2. **Pinned size.** `tlb_mmu_init()` points `fast->table` and `desc->fulltlb`
   at the static storage in `neg`. `tlb-bounds.h` sets the minimum, default
   and maximum sizes equal, so `tlb_mmu_resize_locked()` always returns on its
   existing `new_size == old_size` branch. `tlb_destroy()` frees nothing.
3. **No victim TLB.** `victim_tlb_hit()` returns false, and
   `tlb_set_page_full()` skips the eviction.
4. **`se_addend`.** `mmu_lookup1()` computes `haddr` from it in native
   `CONFIG_SYMBEX_MP` builds. `tlb_set_page_full()` builds the new entry in a
   local variable and copies it over the live one, so it must set
   `tn.se_addend` to 0.
5. **libs2ecore hooks.** Four sites, each placed where upstream has the MMU
   index and the entry index at hand:
   - `tlb_set_page_full()`, before `desc->fulltlb[index] = *full`:
     `flush_tlb_cache_page(old object_state, mmu_idx, index)`. The hook must
     run before the overwrite, because `updateTlbEntry()` finds the reference
     to drop from `m_tlbMap` through the old `object_state`. Today the field
     survives a refill, and upstream overwrites both the fast entry and the
     full entry.
   - `tlb_set_page_full()`, after the new entry is copied in:
     `update_tlb_entry()` for RAM pages.
   - `tlb_flush_one_mmuidx_locked()`: a new hook,
     `flush_tlb_cache_mmuidx(mmu_idx)`, which drops the references of that
     index and sets their `object_state` to NULL. The existing
     `flush_tlb_cache()` clears the whole map and cannot be used here.
     Upstream tracks large pages per MMU index, and `tlb_flush_page_locked()`
     flushes a single index when the page lies in that index's large-page
     region. Clearing the whole map at that point would leave the other
     index with live entries that `updateTlb()` no longer finds, and their
     `se_addend` would go stale at the next copy-on-write.
   - `tlb_flush_page_locked()` and `tlb_flush_range_locked()`, before each
     call to `tlb_flush_entry_locked()` that hits:
     `flush_tlb_cache_page()`. `tlb_flush_entry_mask_locked()` itself only
     receives the entry pointer.

   The `g_se_disable_tlb_flush` guard goes at the top of the three functions
   that every public flush reaches: `tlb_flush_by_mmuidx_async_work()`,
   `tlb_flush_page_by_mmuidx_async_0()` and
   `tlb_flush_range_by_mmuidx_async_0()`.
6. **`se_mmu_resolve()`** called from `mmu_lookup()`, and the memory trace
   calls in `do_{ld,st}{1,2,4,8}_mmu`, per the table in 2.4. `do_ld_*` and
   `do_st_*` are not edited.
7. **`TLB_MEM_TRACE` and `TLB_SYMB_MMIO` at fill time.** `tlb_set_page_full()`
   adds the first to `read_flags` and `write_flags` when a memory access
   signal has subscribers, as `tlb_set_page()` does today, and the second
   when `g_sqi.mem.is_mmio_symbolic()` is true for the page. Both are added
   after the `MMU_INST_FETCH` comparator is set.
8. **Bitcode build.** `SE_NATIVE` (2.4), the entry code in `mmu_lookup()`,
   the concretization in `tlb_index()` (hazard 5.5), and the three hook calls
   by name (hazard 5.4).
9. **Jump cache**, temporary (section 3).
10. **Code fetches ignore the S2E flags.** In `probe_access_internal()`, the
    S2E flags are masked out when `access_type` is `MMU_INST_FETCH`.
    libs2ecore sets `TLB_SYMB` on `addr_code` so that `cpu_ld*_code_mmu()`
    concretizes symbolic code bytes instead of reading stale ones through
    `se_addend`. Without the mask, `probe_access_internal()` would report
    the page as MMIO, `get_page_addr_code_hostp()` would return -1, and the
    callers would abort on any code page that holds symbolic data. The old
    `get_page_addr_code()` ignores the flags in the same way.

For data accesses, `probe_access_internal()` needs no deviation. It reports
any flag it does not know as `TLB_MMIO` with a NULL host pointer, so a caller
that probes a page carrying `TLB_SYMB` or `TLB_NOT_OURS` falls back to the
`cpu_*_mmu` functions and never receives a host pointer that bypasses the
checks. The old helpers do not probe; this matters for the phase 3 helpers.


## 5. Hazards

**5.1 Codegen and C must agree on the entry layout.** The backend hard-codes
`offsetof(CPUTLBEntry, addr_read)`, `addr_write`, `se_addend` and
`CPU_TLB_ENTRY_BITS`. `tlb-common.h` is the single definition for both
components. A build-time assertion on `sizeof(CPUTLBEntry)` exists upstream; add
one on `offsetof(CPUTLBEntry, se_addend)`.

**5.2 The `f[]` index convention.** Upstream's `cpu_tlb_fast()` inverts the
index (`NB_MMU_MODES - 1 - mmu_idx`); libtcg's `tlb_mask_table_ofs()` and
`state.h` do not. `cputlb.c` reaches `f[]` only through `cpu_tlb_fast()`, which
lives in the hand-written `state.h`, so the non-inverted convention stays and
costs no deviation. Check after the import that no `&tlb->f[i]` remains outside
the init and flush loops, where the order does not matter.

**5.3 `ldst_atomicity.c.inc` cannot be used as is in symbex builds.** Three
problems, two of them in the bitcode build and one in the native build:

- The file reaches inline assembly (`vmovdqa`) through the x86-64 host header
  `atomic128-ldst.h`, and KLEE cannot execute inline assembly.
- `load_atom_N()` and `required_atomicity()` branch on the alignment of the
  host pointer. KLEE forks on that branch when the in-page offset is
  symbolic, although both sides compute the same value.
- An unaligned `load_atom_{2,4,8}()` reads the 16 aligned bytes around the
  address and relies on the host page offset of the pointer to stay inside
  the page. In native `CONFIG_SYMBEX_MP` builds `haddr` points into a KLEE
  concrete buffer, which is a 4096-byte heap block with no page alignment,
  so the load can read up to 8 bytes past its end.

In every `CONFIG_SYMBEX` build, native and bitcode, `cputlb-symbex.c.inc`
therefore redirects `load_atom_N()` and `store_atom_N()` to plain
`ldN_he_p()` / `stN_he_p()` and `required_atomicity()` to `MO_8`, with
`#define`s placed after the `#include "ldst_atomicity.c.inc"` line. The
imported file is not edited, and its own functions become unused statics.
Atomicity adds nothing in these builds: there is one vCPU, and KLEE runs one
state at a time. The plain build keeps upstream's behavior. The 16-byte entry
points (`helper_ld16_mmu`, `cpu_ld16_mmu`) are left out of the bitcode build
until the phase 3 frontend emits 128-bit accesses.

**5.4 Calls through `tcg_ops` from bitcode reach the native hooks.**
`cpu->tcg_ops` holds native function pointers. KLEE can call them: it
registers the target address as an external function. A native call forks
once per possible value of each symbolic argument, though, and three hooks
receive the access address: `tlb_fill()` in `tlb_fill_align()`,
`pointer_wrap()` in `mmu_lookup()` and `do_unaligned_access()` in
`cpu_unaligned_access()`. In the bitcode build these three sites call the x86
functions by name, which selects their bitcode copies in `op_helper.bc`.

**5.5 The lookup must not index the TLB with a symbolic value.** If the index
depends on the symbolic address, KLEE treats the table access as a symbolic
pointer into the TLB object. `mmu_lookup1()` computes the index for both pages
of an access, and `mmu_lookup()` computes it again after a possible resize.
All of these go through `tlb_index()`, so the bitcode build concretizes the
page number there, in one place, and `tlb_entry()` inherits it.

**5.6 Return address conventions.** `se_mmu_resolve()` decides between
`switch_to_symbolic()` and concretization with `tcg_is_dyngen_addr(ra)`. The
compatibility macros pass 0, which selects concretization, as today. The
`helper_*_mmu` functions receive the address from the backend's slow path.
Check that the value still satisfies `tcg_is_dyngen_addr()` once the backend
calls the helpers directly. The phase 3 helpers pass `GETPC()`, which is an
address in generated code, so the test will then select
`switch_to_symbolic()` for helpers too. Phase 3 has to decide whether its
helpers can be restarted at that point, or pass the distinction another way.

**5.7 Watchpoints change mechanism.** The old code routes watched pages
through an IO section (`phys_section_watch`) and `mem_io_vaddr`. Upstream sets
`TLB_WATCHPOINT` and calls `cpu_check_watchpoint()` with the address.
`watchpoint.c` reaches `tb-maint.c` and `cpu-exec.c` functions
(`tb_check_watchpoint()`, `cpu_loop_exit_restore()`, `cflags_next_tb`) that
have old equivalents with different shapes. This is the least-scoped item of
the plan; size it before starting step 3.

**5.8 `MemOpIdx` width.** libtcg's `tcg/tcg-memopidx.h` keeps the MMU index in
the low 4 bits of `oi`; upstream's `include/exec/memopidx.h` uses 5 since
v10.2.0. libtcg's `mapping.tsv` lists the header as tracking upstream's, but
the file still has its 8.1.2 content. Step 2 brings it to `v11.1.0`. The
backend and `cputlb.c` must use one definition, so `cputlb.c` includes
libtcg's header and upstream's is not imported into libcpu a second time.

**5.9 `TLB_NOTDIRTY` stays set while an S2E flag is set.** Upstream's
`tlb_set_dirty1_locked()` clears the flag only when the write comparator
equals `addr | TLB_NOTDIRTY` exactly. The old `tlb_set_dirty1()` masks
`TLB_SYMB` out of that comparison. With upstream's text, a page that carries
`TLB_SYMB`, `TLB_NOT_OURS` or `TLB_MEM_TRACE` keeps `TLB_NOTDIRTY`, and every
store to it calls `notdirty_write()` again. The result is correct, and these
stores already take the slow path, so this is left without a deviation.
`notdirty_write()` tries again on each store and succeeds once the S2E flags
are gone.


## 6. Steps

Each step ends with all six targets building. Steps 1 and 2 change no
behavior.

### Step 1: Tooling

Create `libcpu/scripts/upgrade/{BASELINE,mapping.tsv}` with an
`# upstream-dirs:` header (`PORTING.md` phase 0). Check that
`normalize.sh` emits `accel/tcg/cputlb.c` into `src/accel/cputlb.c`.

### Step 2: Preparation, with the old softmmu still in place

- Update libtcg's `tcg/tcg-memopidx.h` to upstream's `v11.1.0` text, as its own
  commit (hazard 5.8). Three sites extract the MMU index with a hard-coded
  `& 0xf` and must call `get_mmuidx()` first: two in `softmmu_template.h` and
  one in `MMUFunctionHandlers.cpp`. All other users go through the accessors.
  The header keeps two deviations: the `(MemOp)` cast in `get_memop()`, which
  `tcg-llvm.cpp` needs to compile the header as C++, and the include of
  `tcg-memop.h` in place of `exec/memop.h`. The assertions under
  `CONFIG_DEBUG_TCG` use `clz32()`, so `host-utils.h` must be visible there.
- Write `src/s2e/mem-shim.h` and its dirty-tracking half.
- Add the stub headers and import the plain headers of 2.1 that do not conflict
  with existing definitions (`cpu-ops.h`, `vaddr.h`, `memattrs.h`,
  `mmu-access-type.h`, `page-protection.h`). `page-protection.h` replaces
  libtcg's `tcg/cpu.h`, which is deleted here.
- Write the four `TCGCPUOps` hooks in `op_helper.c` and set `cpu->tcg_ops`.
  Nothing calls them yet.
- Add `softmmu-compat.h`, initially mapping the old names onto themselves, and
  include it where `softmmu_exec.h` is included. This fixes the include graph
  before the switch.
- Split the watchpoint code out of `exec-bp.c` so that step 3 replaces one
  file.

**Exit:** the tree builds and boots unchanged.

### Step 3: The switch

The TLB layout is shared by `cputlb.c`, libtcg's backend and libs2ecore, so
this lands as one change. Bring the targets up in this order on the branch:

1. **`{i386,x86_64}-softmmu`.** Import the files of 2.1 with deviations 1, 2, 3
   and 9. Replace `CPUTLB`, `CPUTLBDesc` and `CPUTLBEntry`. Apply the libtcg
   removals of 2.1 in the same change: split `tcg/tlb.h`, drop the TLB size
   macros from `tcg/tcg.h`, delete `atomic-helpers.c` and move the two atomic
   template rows to libcpu's `mapping.tsv`. The atomic files cannot move
   earlier, because the upstream template bodies call `atomic_mmu_lookup()`,
   which `cputlb.c` defines. Delete the helper override tables, restore the
   backend slow path, and put `libcpu.a` and `libtcg.a` in one linker group.
   Point the compatibility header at the new API. Convert the
   `tlb_flush(env, 1)` and `tlb_flush_page(env, addr)` callers to the
   `CPUState *` signatures, and the one `tlb_set_page()` caller. Delete the
   old files.
2. **`-s2e_sp-softmmu`** (single path). Add deviations 5, 7 and 10 with the
   new `flush_tlb_cache_mmuidx()` hook, the redirections of hazard 5.3, the
   memory trace calls of deviation 6, the bitcode build of `cputlb.c` with
   deviation 8, and the `tcg-llvm.cpp` change. Rewrite
   `MMUFunctionHandlers.cpp`. Update the `__DEFINE_EXT_FUNCTION` list.
3. **`-s2e-softmmu`.** Add deviation 4 and `se_mmu_resolve()`. Port
   `S2EExecutionStateTlb` to the new layout: `object_state` in
   `CPUTLBEntryFull` and the flags at their new comparator bits. The `CPU_TLB_SIZE` sites that index the
   main TLB switch to `tlb_index()`-style mask reads; the `se_ram_tlb` sites
   keep their own constant.

**Exit:** a guest boots on all six targets. With the TLB audit enabled
(`ba81a679`), a symbolic run reports no inconsistency. The testsuite passes,
including these cases:

- a symbolic in-page offset with `fork-on-symbolic-address` disabled;
- code executed from a page that also holds symbolic data (deviation 10);
- a page fault taken in KLEE at an address that is not page-aligned, checking
  the CR2 value that the guest reads (2.4);
- a guest that maps the same region with a large page and flushes one page of
  it while other entries are live (deviation 5).

### Step 4: Cleanup

- Delete `mem_io_vaddr`, `S2EExecutionState::setMemIoVaddr()`,
  `g_sqi.mem.read_mem_io_vaddr` and `tcg_llvm_write_mem_io_vaddr`. Upstream
  passes the address to `notdirty_write()` and `cpu_check_watchpoint()`
  directly.
- Delete `se_tlb_current`. `do_ld_*` and `do_st_*` receive the
  `CPUTLBEntryFull` they need.
- Delete the `ld*_raw_symb` accessors and the `_kernel_symb` instantiation.
- Update `PORTING.md` (phases 1, 2, 6, and section 9.6, which still describes
  editing `softmmu_header.h`) and `tlb-update.md` section 6.


## 7. Symbolic MMIO pages get their own flag

Today RAM pages that contain symbolic MMIO or DMA ranges are marked by reusing
`TLB_NOTDIRTY` on reads and `TLB_MMIO` on writes. Upstream gives
`TLB_NOTDIRTY` a write-only meaning and reads `TLB_MMIO` as "no host memory",
so the reuse does not carry over.

These pages are marked with `TLB_SYMB_MMIO`, the one slow flag bit that
upstream leaves free (2.2). The flag is known when the entry is filled and
never changes afterwards, so `tlb_set_compare()` handles it without help from
libs2ecore.

Reusing `TLB_SYMB` for these pages was considered and rejected. The bitcode
build ignores `TLB_SYMB`, so it would stop calling
`tcg_llvm_trace_mmio_access()` for them, and libs2ecore clears `TLB_SYMB`
whenever the page becomes fully concrete.


## 8. What this leaves alone

- The rest of `accel/tcg`: `cpu-exec.c`, `tb-maint.c`, `translate-all.c`,
  `translator.c`. The TB hash, the jump cache structure and `precise-pc.c` do
  not change.
- The i386 frontend and helpers, `NB_MMU_MODES`, and the MMU index values.
- The RAM TLB (`se_ram_tlb`) and `S2EExecutionStateTlb`'s ownership model.
- Dynamic TLB sizing and the victim TLB. Both need the TLB to move or reorder
  entries under libs2ecore, which the bitcode softmmu and `m_tlbMap` do not
  support (`tlb-update.md` section 5, `PORTING.md` 9.4).
- The atomic helpers (`cpu_atomic_*_mmu`). They are compiled natively but have
  no caller and no symbolic path until phases 3 and 6. `atomic_mmu_lookup()`
  returns a host pointer, so it will need the same treatment as
  `probe_access()` when a caller appears.
