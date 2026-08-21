# Rebuilding libcpu on QEMU 11.1

libtcg tracks QEMU `v11.1.0`. libcpu is the last QEMU-1.0 island in the tree, and
the gap is too wide to merge: it gets rebuilt from upstream instead. This
document is the plan for doing that **concrete execution first**, keeping S2E's
KVM-shim architecture and leaving symbolic execution to land on top afterwards.

Measured against `~/qemu` at `v11.1.0` and this tree at `9982579d`.

| | |
|---|---|
| Source | qemu `v11.1.0` |
| Replaces | ~22k of libcpu's 29.4k lines |
| Imports | ~51k lines |
| Targets | `{i386,x86_64}-softmmu`, then the `-s2e` and `-s2e_sp` variants |
| Estimated effort | 12-17 weeks to concrete parity, 18-26 to full parity |


## 1. What libcpu is today

Two properties of the current design shape the rest of this plan.

First, `libs2e.so` is preloaded into a stock QEMU process and impersonates
*KVM*: libcpu is the kernel module, not the emulator. Device models, machine
setup, migration and the monitor all live in the real QEMU on the other side of
the ioctl boundary. So "no hardware emulation" is not a restriction this plan
imposes; it is already the shape of the system, and it removes most of what
makes upstream QEMU hard to extract.

Second, libtcg has already been through this exercise. It is a de-QEMU-ified
fork at `v11.1.0` with a normalize-then-three-way-merge upgrade path
(`libtcg/scripts/upgrade/`), and it is *almost* free-standing: the only symbol it
needs from libcpu today is `helper_lookup_tb_ptr`. The boundary is already clean.

### Fate of the current tree

| File | Lines | Fate | Replaced by / note |
|---|---:|---|---|
| `target-i386/translate.c` | 7,992 | replace | `target/i386/tcg/{translate.c, decode-new.c.inc, emit.c.inc}` |
| `target-i386/op_helper.c` | 5,972 | replace | splits into 12 upstream helper files |
| `target-i386/ops_sse.h` | 1,891 | replace | `target/i386/ops_sse.h` (2,672) |
| `target-i386/helper.c` | 1,119 | replace | `helper.c` + `cpu-dump.c` + `tcg/excp_helper.c` |
| `target-i386/cpu.h` | 480 | replace | merged into the new `include/cpu/i386/cpu.h` |
| `softmmu_{template,header,exec}.h` | 1,162 | replace | `cputlb.c` + `ldst_common.c.inc` |
| `cpu-exec.c`, `exec-tb.c`, `exec-tlb.c`, `exec-phystb.c`, `exec-bp.c`, `translate-all.c`, `exec.c` | 2,766 | replace | `accel/tcg/{cpu-exec, tb-maint, cputlb, translate-all, translator, watchpoint}.c` |
| `target-i386/cpuid.c` | 1,029 | replace | the CPUID/feature-model subset of `target/i386/cpu.c` (~8.0k lines) |
| `include/cpu/i386/cpuid.h` | 176 | replace | `cpuid_t` and its 2011-era feature bits die; `FeatureWordArray` replaces them |
| `exec-ram.c`, `exec-phys.c`, `exec-memdbg.c`, `memory.c`, `ioport.c` | 1,241 | adapt | S2E's `MemoryDesc` layer, the replacement for `MemoryRegion`; count includes the matching headers |
| `cpus.c`, `timer.c`, `disas.c` | 555 | keep | reduced QEMU files plus the S2E-original capstone disassembler |
| `precise-pc.c` | 221 | reconcile | upstream `translate-all.c` restore machinery + S2E's `tb_get_instruction_size()`; collides with the phase 2 import (see section 8) |
| `include/cpu/kvm.h` | 1,335 | keep | the ioctl ABI; untouched by this work |

Roughly 22k lines go away and ~51k arrive: 8.3k from `accel/tcg/`, 31.5k from
`target/i386/` plus ~8.0k of CPUID machinery from `target/i386/cpu.c`, and ~3.2k
of utilities. The line count grows because upstream's i386 frontend (the new
table-driven decoder, full AVX/AVX2 emit paths, XSAVE, MPX) and its feature model
are much larger than the 2011 ones. That growth is most of the point of doing
this.


## 2. The method: reuse libtcg's, don't invent one

"Start from scratch" should mean *start from upstream files*, not hand-write new
ones. Take the same route libtcg took, so that the second upgrade (11.1 to
12.x) is a three-way merge and not another rebuild:

1. Run each upstream file through `clang-format` with the S2E style *before* it
   enters the tree.
2. Rewrite its includes to libcpu/libtcg paths and add `extern "C"` guards.
3. Record the pairing in `libcpu/scripts/upgrade/mapping.tsv`, with `BASELINE` =
   `v11.1.0`.
4. Confirm normalization by merging the tag onto itself:
   `./merge.sh v11.1.0 v11.1.0` must report zero conflicts.

`libtcg/scripts/upgrade/{normalize.sh,merge.sh}` already do steps 1 and 4; they
need a tree-root parameter so they can serve both components. Every S2E
deviation introduced from here on gets a comment saying *why*, because the merge
tool cannot preserve intent it cannot see.

libcpu's current state is exactly what happens without this discipline: fourteen
years of drift that can no longer be merged. The tooling is cheap, a day or two
in phase 0, and it is the only thing that stops the next upgrade from being
another rebuild.


## 3. Five decisions that constrain the rest

Everything else follows from these. They should be settled before any code is
imported.

### 3.1 Hand-write a slim `CPUState`; do not import QOM

Upstream splits the CPU into `ArchCPU { CPUState parent_obj; CPUX86State env; }`,
where `CPUState` derives from `DeviceState` -> `Object`. Importing that chain
means `qom/object.c`, `hw/core/qdev*.c`, properties, resettable and hotplug, a
large device-oriented dependency for a component with no devices.

That chain is not needed. Measured over the accel/tcg files we import, only
about twenty `CPUState` fields are ever touched: `neg` (59 uses), `cc` (26, all
of them `cpu->cc->tcg_ops->...`), `exception_index`, `cflags_next_tb`,
`tb_jmp_cache`,
`jmp_env`, `interrupt_request`, `exit_request`, `halted`, `breakpoints`,
`watchpoints`, and a handful more. So: define a plain struct with exactly those
fields, keep upstream's *layout contract* (`CPUNegativeOffsetState neg` last in
`CPUState`, `CPUX86State` immediately after it, so `cpu_env()` / `env_cpu()` and
the negative TLB offsets work unmodified), and replace `cpu->cc` with a direct
`const TCGCPUOps *`. `TCGCPUOps` itself is a plain function-pointer struct and
imports as-is.

- Cost: ~200 lines of hand-written header, in `libcpu/include/cpu/state.h`.
- Buys: accel/tcg and target/i386/tcg compile essentially unmodified.
- Risk: **low**. Fields are added on demand; a missing one is a compile error,
  not a silent bug.

### 3.2 Keep `MemoryDesc`; graft it into `CPUTLBEntryFull`

S2E already has the right abstraction. `MemoryDesc` wraps a
`kvm_userspace_memory_region` plus a `{read, write}` op pair; `mem_desc_find(gpa)`
returns NULL for MMIO. That is exactly the information `MemoryRegionSection`
carries for our purposes, without FlatView, AddressSpace, RCU flatview swaps or
the `MemoryRegion` type hierarchy.

The coupling in `cputlb.c` is concentrated in about eight places, all of which we
rewrite:

- `tlb_set_page_full()`: drop `address_space_translate_for_iotlb`,
  `memory_region_is_ram/romd`, `memory_region_get_ram_ptr/addr`.
- `io_prepare()` / `io_failed()`.
- `int_ld_mmio_beN` / `int_st_mmio_leN`: dispatch through `MemoryDescOps`
  instead of `memory_region_dispatch_read/write`.

Replace `CPUTLBEntryFull`'s `MemoryRegionSection *section` pointer and
`xlat_offset` with `const MemoryDesc *` plus an offset. 11.1's `io_prepare()`
already dereferences `full->section` directly, which keeps the graft local.
Dirty-page tracking keeps the existing `exec-ram.h`
byte-per-page mask rather than upstream's bitmap trio.

- Cost: ~300 lines of rewritten `cputlb.c` plus a compatibility header.
- Buys: no MemoryRegion, no AddressSpace, no BQL around memory dispatch.
- Risk: **medium**. These functions are re-touched by upstream regularly, so they
  will conflict at every future merge. Isolate them behind a thin `s2e_mem_*`
  layer so the conflicts stay small.

### 3.3 Adopt upstream's TLB, and take it out of the execution state

libtcg's x86_64 backend is already the v11.1 one and already knows about the S2E
TLB: it emits the `se_addend` load on the hit path (under `CONFIG_SYMBEX_MP`
only; the non-MP symbex build uses the plain `addend`), and it locates the TLB
through `TCGContext::tlb_fast_offset`. That is the *only* live geometry field:
`tlbe_size`, `tlbe_offset_*`, `cpu_tlb_size`, `cpu_tlb_entry_bits` and
`env_ptr` are set by `translate-all.c` and read by nothing. The backend
hard-codes `offsetof(CPUTLBEntry, ...)` and `CPU_TLB_ENTRY_BITS`, so a
`CPUTLBEntry` layout change still means editing the backend in lock-step. What
makes this decision cheap is narrower but sufficient: the generated code reads
`mask` and `table` out of `CPUTLBDescFast` at run time, so a dynamically sized
table needs no codegen change. Point `tlb_fast_offset` at
`offsetof(ArchCPU, neg.tlb.f) - offsetof(ArchCPU, env)`, the value the current
`translate-all.c` already documents in a comment next to the S2E override.

Take upstream's dynamic, heap-allocated TLB as-is, and **stop storing it in the
execution state**, flushing it on every state switch instead. It is a cache of a
mapping derivable from the guest page tables and the KLEE address space, and a
state switch already discards the whole translation block cache and round-trips
the entire QEMU device model, both of which cost far more than refilling it.
Disable the victim TLB initially, and move S2E's flags into
`CPUTLBEntryFull.slow_flags[]`. Section 9 is the full analysis; the summary:

- Cost: mostly deletion. `exec-tlb.c` goes away, and so do ~216 KB of per-state
  cache. The main-TLB `CPU_TLB_SIZE` sites in libs2ecore become run-time mask
  reads (the `se_ram_tlb` sites keep a pinned size; see 9.2).
- Buys: smaller per-state memory, faster state switches, and `objectState` gets
  a better home in `CPUTLBEntryFull` than in the fast entry. `cputlb.c` still
  needs one contained deviation (a pinned TLB size, two functions) because
  the TLB stays KLEE-visible and KLEE bindings cannot be re-created per state.
  See `tlb-update.md` section 5.
- Risk: **medium**. `CPUTLBEntry` must stay a power-of-two size; the
  `TCGContext` geometry fields must track the layout; and codegen and C code must
  agree on whether the `CPUTLBDescFast` array index is inverted.

### 3.4 Move to upstream's helper ABI and retire the global `env`

Today's helpers take no `env` (`DEF_HELPER_0(cpuid, void)`) and reach a
file-scope `CPUArchState *env`, with `EAX`-style macros expanding to
`RR_cpu()` (`EIP` and `DF` deliberately bypass it; they live outside the
symbolic prefix). Upstream passes `env` explicitly
(`DEF_HELPER_1(cpuid, void, env)`) and writes `env->regs[R_EAX]` directly.
Trying to keep the old convention would mean rewriting every imported helper.

Take upstream's convention. Two consequences to plan for now, not later:

- The per-target helper list currently lives in libtcg
  (`libtcg/include/tcg/helper.h`, hard-wired via `HELPER_H` in
  `exec/helper-gen.h`). That is a layering wart: the file is target-specific and
  belongs in libcpu. Make `HELPER_H` resolve to a libcpu path as part of phase 3,
  not as cleanup afterwards.
- The `RR_cpu` / `WR_cpu` discipline that makes helpers correct inside KLEE has
  to be reintroduced mechanically over the new helper sources in phase 6. See
  section 7.

Cost: the helper list moves; the dead `tcg_ctx->env_ptr` and geometry fields
(see 3.3) get deleted; the live handle in 11.1 is `tcg_env`. Buys:
helper files import unmodified, and it fixes the current ABI smell where libcpu
installs `(env, addr, mmu_idx, retaddr)` helpers into slots libtcg marshals as
`(env, addr, oi, retaddr)`. Risk: **high, deferred**. This is the decision most
entangled with symbolic execution. It is still the right one; section 7 lists the
invariants that keep it safe.


### 3.5 Take the CPUID and feature model from 11.1 too

The current `cpuid.c` is a QEMU-1.0 artifact and it is the *definition* of the
CPU S2E exposes, not just a consumer of it. The data flow is:
`cpu_x86_register(&m_cpuid, model, is64)` builds a `cpuid_t` from libcpu's own
model table; `KVM_GET_SUPPORTED_CPUID` answers the QEMU process out of it via
`cpu_x86_cpuid()`; QEMU filters and hands the result back through
`KVM_SET_CPUID2`. Whatever `cpuid_t` cannot express, the guest never sees.

`cpuid_t` has seven feature words, all of them pre-2011. Upstream has 48
`FeatureWord`s, and 11.1's decoder gates on them: `FEAT_7_0_EBX` for
AVX2/BMI1/BMI2, `FEAT_XSAVE`, `FEAT_7_1_EAX`, and so on. Keeping the old
`cpuid_t` would mean importing the new frontend and then being unable to
advertise most of what it can now emulate. So `cpuid.c` and
`include/cpu/i386/cpuid.h` are replaced, not kept.

What to take from `target/i386/cpu.c`:

| Piece | Lines | Why |
|---|---:|---|
| `TCG_*_FEATURES` masks + `feature_word_info[]` | 2,668 | The feature word model, and `.tcg_features`, the ceiling on what TCG can actually emulate, which is exactly the right bound for what S2E advertises. The count includes the cache-descriptor tables between the two, which `cpu_x86_cpuid()` needs anyway. |
| `builtin_x86_defs[]` | 3,813 | The named CPU models (`qemu64`, `Skylake-Client`, ...) that `-cpu` selects. |
| `cpu_x86_cpuid()` | 735 | The leaf implementation itself. |
| `x86_cpu_expand_features()`, `x86_cpu_filter_features()` | 367 | Applies the tcg mask and expands dependent features. |
| `x86_cpu_get_supported_feature_word()` | 244 | Reduce to the TCG branch; drop kvm/hvf/whpx/nvmm/mshv. |
| `x86_cpu_load_model()` | 155 | Model name to feature words. |
| `x86_update_hflags()` | 42 | Needed regardless. |
| | **~8,000** | of `cpu.c`'s 11,034 |

The remaining ~3k lines are QOM: `x86_cpu_realizefn`, class init, property
tables, hyperv plumbing. Those we replace with a direct call path, consistent
with decision 3.1.

Note that `cpu_x86_cpuid()` reaches `X86CPU` fields through `env_archcpu(env)`:
`phys_bits`, `guest_phys_bits`, `enable_l3_cache`, `legacy_cache`,
`cache_info_cpuid4` and friends. Those become plain fields on the slim `ArchCPU`
from decision 3.1, set once at init instead of through QOM properties.

## 4. Dependencies, and where they should live

**libcpu uses exactly one header from libutils today: `qqueue.h`** (QTAILQ, for
breakpoint and watchpoint lists). Everything else in libutils (QAPI,
QObject/QDict/QJSON, the visitors, coroutines, fsigc++) is consumed by libs2e
and libs2ecore, not by the CPU emulator. libutils is therefore *not* on the
critical path for this port; the question is only where the new dependencies go.

### 4.1 The placement rule: platform-independent code belongs in libutils

libtcg is configured per target: the build produces six trees per build type
(`{i386,x86_64}` x `{plain, s2e, s2e_sp}`), and every one of them rebuilds
libtcg from scratch. libutils is configured once per build type. So anything that
does not depend on `TARGET_LONG_BITS`, `TARGET_PAGE_BITS`, `CONFIG_SYMBEX` or the
CPU state belongs in libutils, and putting it in libtcg costs six compilations of
the same object.

libtcg already declares `find_package(LIBUTILS REQUIRED)`, so the dependency edge
exists and nothing new has to be wired up.

**This applies to what is already there, not only to the new imports.** That
relocation is done: libtcg's `utils/` subset moved to `libutils/include/utils/`
and `libutils/src/utils/`, and the include prefix is now `<utils/...>`, matching
libutils' existing flat `<qqueue.h>` / `<coroutine.h>` shape.

Three files stayed behind in `libtcg/include/tcg/utils/`. `utils/log.c` has
three `#ifdef TARGET_I386` / `#ifdef CONFIG_SYMBEX` blocks that populate the
`CPU_LOG_*` mask table (`log.h` itself is clean); `utils/bswap.h` tests
`TARGET_WORDS_BIGENDIAN` and `TARGET_LONG_SIZE` in live code and is mapped to
upstream `include/qemu/bswap.h`, so it cannot be edited to drop the dependency
without creating a merge deviation; `utils/cpu-float.h` needs the softfloat
types, which stay with libtcg. Making the log-mask table registrable and
splitting bswap's target-dependent tail into a libcpu header would let the
first two follow, but neither is on the critical path.

`utils/qtree.h`, `utils/int128.h` and `utils/host-utils.h` read
`HAVE_GLIB_WITH_SLICE_ALLOCATOR`, `CONFIG_INT128` and `HOST_BIG_ENDIAN`.
`libutils/src/CMakeLists.txt` defines them for its own objects; every component
that includes these headers has to define them identically, or struct layouts
disagree across translation units.

The upgrade tooling followed the files: libutils now has its own
`scripts/upgrade/{BASELINE,mapping.tsv,merge.sh,normalize.sh}`, and the 28
corresponding rows moved out of libtcg's mapping. Both components report zero
conflicts under `merge.sh v11.1.0 v11.1.0`.

### 4.2 What 11.1 needs that we do not have

Resolving the include closure of the accel/tcg import set against libtcg's
vendored utils gives a short list. Placement follows the rule above.

| Needed by 11.1 | Lines | Status | Recommendation |
|---|---:|---|---|
| `qemu/qht.{h,c}` | 1,254 | missing | Import into **libutils**. The TB hash table; `tb-maint.c` and `cpu-exec.c` use it directly. |
| `qemu/rcu.{h,c}` | 693 | missing | Import into **libutils**. Required by qht. Could be stubbed for the single-vCPU case, but importing costs less than reasoning about the stub. |
| `qemu/thread{,-posix}.h`, `util/qemu-thread-posix.c` | 934 | missing | Import a reduced subset (mutex, cond, thread) into **libutils**. libtcg's `utils/mutex.h` is a partial stand-in that should be folded into it. |
| `qemu/xxhash.h`, `qemu/seqlock.h` | ~330 | missing | Import into **libutils**; header-only, no further deps. |
| `qemu/qdist.{h,c}` | ~440 | missing | **Skip.** Only feeds `qht_statistics`; compile it out. |
| `qemu/error-report.h`, `qemu/qemu-print.h` | ~120 | missing | Thin S2E versions in **libutils**, routing to the log. |
| `qemu/main-loop.h` (BQL) | n/a | missing | **Stub** in libcpu. `bql_lock`/`bql_unlock` as no-ops; one vCPU, no MTTCG. |
| `exec/icount.h`, `exec/replay-core.h`, `system/tcg.h`, `qemu/plugin.h`, `qemu/target-info.h` | n/a | missing | **Stub** in libcpu; these are configuration-dependent. icount off, replay off, `tcg_enabled()` is true, plugins compiled out. |
| `qemu/queue.h` | n/a | have | libutils `qqueue.h`, already in the right place. |
| glib allocation shims (`g_new`, `g_try_new`, `g_free`, `GArray`) | n/a | verify | Used by `qht.c`, `cputlb.c`, `tb-maint.c`; confirm libtcg's existing glib-compat covers the import closure, extend in **libutils** if not. |
| osdep, cutils, bitops, bitmap, int128, host-utils, atomic, atomic128, interval-tree, qtree, memalign, cacheinfo, units, cpuid | ~7,140 | have | Moved to `libutils/include/utils/` and `libutils/src/utils/` per 4.1. |
| bswap | 308 | have, target-dependent | Tests `TARGET_WORDS_BIGENDIAN` / `TARGET_LONG_SIZE`; stayed in libtcg with log unless its target tail is split out (see 4.1). |
| log | 238 | have, target-dependent | Stayed in libtcg unless the `CPU_LOG_*` mask table is made registrable. |

Net: about 3.2k lines of newly imported utility code, on top of the ~7.1k-line
relocation that already removed five redundant compilations of each object per
build type. The dependency work is not what makes this project long.

## 5. What is deliberately not ported

| Upstream | Why not |
|---|---|
| `hw/**`, `system/memory.c`, `system/physmem.c` | Devices and machine memory live in the host QEMU process, behind the KVM ioctl boundary. `MemoryDesc` replaces the parts we need. |
| `qom/**`, `hw/core/qdev*` | Decision 3.1. No devices means no object model. |
| `target/i386/cpu.c`, the QOM half (~3k lines) | `x86_cpu_realizefn`, class init, property tables, hyperv and accel glue. The other ~8.0k lines (the feature model and CPUID) *are* ported; see section 3.5. |
| `target/i386/machine.c`, `migration/**` | Snapshots are handled by vanilla QEMU, not by libcpu. |
| `accel/tcg/tcg-accel-ops*.c`, `icount-common.c` | MTTCG, round-robin scheduling and icount. One vCPU, driven by `KVM_RUN`; `cpus.c` and `timer.c` stay. |
| `accel/tcg/plugin-gen.c`, `plugins/**` | TCG's plugin API duplicates what S2E's core-plugin hooks already do. Compile out; revisit only if it turns out to be a cheaper hook point than patching `translate.c`. |
| `gdbstub/**`, `monitor/**`, `disas/**` | Debugger and monitor belong to host QEMU. Disassembly stays on capstone via `disas.c`. |
| `target/i386/{kvm,hvf,whpx,nvmm,mshv,sev}/**` | Other accelerators. TCG only. |
| `target/i386/tcg/user/**`, `accel/tcg/user-exec*.c` | linux-user mode. Softmmu only. |


## 6. The plan, phase by phase

Phases 0-4 deliver a working concrete emulator. Phases 5-6 put S2E back on top.
Each phase ends at something you can build and check, so the tree is never left
in a state nobody can reason about. Estimates assume one person familiar with the
codebase.

### Phase 0: Tooling and scaffolding (~1 week)

- Generalize `libtcg/scripts/upgrade/{normalize.sh,merge.sh}` to take a component
  root, so libcpu can drive them; or fork them into `libcpu/scripts/upgrade/` if
  that turns out cleaner.
- Create `libcpu/scripts/upgrade/{BASELINE,mapping.tsv,README.md}`. `BASELINE` is
  `v11.1.0` from the start; `mapping.tsv` grows as files land.
- Settle the target directory layout. Proposal, mirroring libtcg: `src/accel/`
  for accel/tcg files, `src/target-i386/` for the frontend and helpers,
  `src/s2e/` for S2E originals (exec-ram, exec-phys, memory, ioport, cpus, timer,
  disas, precise-pc), `include/cpu/` unchanged as the public surface.
- Create a scratch branch that builds the *current* tree with `CONFIG_SYMBEX`
  off, so the concrete-only configuration is known-good before anything moves.

**Exit:** `./merge.sh v11.1.0 v11.1.0` runs clean over an empty mapping;
`normalize.sh` can emit any 11.1 file into its intended libcpu path;
`x86_64-softmmu` builds and boots on the old code.

### Phase 1: Substrate, utilities, CPUState, memory shim (2-3 weeks)

- **Relocate libtcg's platform-independent utils to libutils** (section 4.1)
  — done. 33 files moved, 77 include lines across 46 files rewritten to
  `<utils/...>`, `utils/{log.h,log.c,bswap.h,cpu-float.h}` left behind, and 28
  mapping rows moved into libutils' new `scripts/upgrade/`.
- Import qht, rcu, thread, xxhash, seqlock into **libutils** per section 4.2; add
  them to libutils' new `mapping.tsv`. Fold libtcg's `utils/mutex.h` into the
  real thread header.
- Write `libcpu/include/cpu/state.h`: slim `CPUState`, `CPUNegativeOffsetState`,
  `ArchCPU`, `cpu_env()` / `env_cpu()`, and the `TCGCPUOps` pointer that replaces
  `cpu->cc`.
- Write the memory shim: upstream's `iotlb_to_section`,
  `memory_region_dispatch_*`, `qemu_ram_addr_from_host*` and the dirty-tracking
  predicates, expressed over `MemoryDesc` and `exec-ram.h`.
- Write the stub headers: BQL, icount, replay, plugins, `tcg_enabled()`,
  target-info.

**Exit:** the substrate compiles standalone against libtcg. A small unit test
drives qht insert/lookup/remove/resize.

### Phase 2: accel/tcg core (2-3 weeks)

- Normalize and import: `cpu-exec.c`, `cpu-exec-common.c`, `cputlb.c`,
  `tb-maint.c`, `translate-all.c`, `translator.c`, `watchpoint.c`, plus
  `tb-hash.h`, `tb-context.h`, `tb-internal.h`, `tb-jmp-cache.h`,
  `internal-common.h`, `backend-ldst.h`, `tlb-bounds.h`, `vcpu-state.h`,
  `ldst_common.c.inc`, `ldst_atomicity.c.inc`, and the atomic helpers
  `atomic_common.c.inc` / `atomic_template.h` that `cputlb.c` pulls in
  (`tcg-runtime*` already lives in libtcg).
- Rewrite the eight `MemoryRegion` touch points in `cputlb.c` against the phase 1
  shim.
- Apply the TLB decisions from section 9: disable the victim TLB, move S2E's flag
  bits into `slow_flags[]`, and move `objectState` into `CPUTLBEntryFull`. If
  `tlb-update.md` has landed first, the ownership half of this is already done
  and `cputlb.c` imports without S2E-side surprises. Bring
  `libtcg/include/tcg/tlb.h` forward to the 11.1 flag scheme at the same time. It
  is an S2E-original that was never upgraded and still describes the pre-11.1
  bit allocation.
- Delete `cpu-exec.c`, `exec.c`, `exec-tb.c`, `exec-tlb.c`, `exec-phystb.c`,
  `exec-bp.c`, `translate-all.c`, `softmmu_*.h`, `cpu-all.h`, `cpu-defs.h`,
  `exec-all.h`.
- Reconcile `libtcg/include/tcg/tb.h` with upstream's `TranslationBlock`: the S2E
  copy has drifted (it still carries `phys_hash_next` and `page_next` from the
  pre-qht era, alongside 11.1's `jmp_*` fields).
- Reconcile `precise-pc.c` with the imported `translate-all.c`: upstream owns
  `encode_search()` and `cpu_restore_state()` there, which `precise-pc.c`
  carries as its own copies, and `precise-pc.c` calls `restore_state_to_opc()`,
  defined in the old `translate.c` that phase 3 replaces and reached in
  11.1 through `TCGCPUOps.restore_state_to_opc`. Keep only the S2E extensions
  (`tb_get_instruction_size()`, `se_restore_state_to_opc()`) and re-home them
  explicitly.

**Exit:** `libcpu.a` builds and links against libtcg with only `target-i386`
symbols undefined.

### Phase 3: The i386 frontend, helpers and CPUID model (5-7 weeks, the bulk)

- Write the new `include/cpu/i386/cpu.h` from upstream's `cpu.h`: strip QOM and
  the model/feature machinery, merge the fields S2E's `X86CPU` equivalents need
  into `ArchCPU`, and **order the fields so the symbolic-capable prefix still
  ends at `eip`** (see section 7).
- Import `helper.h`, `ops_sse.h`, `svm.h`, `cpu-param.h`, `helper.c`,
  `cpu-dump.c`; and from `tcg/`: `translate.c`, `decode-new.{c.inc,h}`,
  `emit.c.inc`, `cc_helper.c`, `cc_helper_template.h.inc`, `excp_helper.c`,
  `fpu_helper.c`, `int_helper.c`, `mem_helper.c`, `misc_helper.c`,
  `mpx_helper.c`, `seg_helper.c`, `seg_helper.h`, `bpt_helper.c`,
  `access.{c,h}`, `tcg-cpu.{c,h}`, `helper-tcg.h`, and the `tcg/system/` variants
  (`smm_helper.c`, `svm_helper.c`, and the system-mode halves of
  excp/misc/seg/bpt/fpu).
- Move `HELPER_H` from `libtcg/include/tcg/helper.h` to a libcpu path; drop
  libtcg's `tcg/ops_sse_header.h` in favor of upstream's `.h.inc`.
- Import the CPUID and feature model per decision 3.5: the `TCG_*_FEATURES`
  masks, `feature_word_info[]`, `builtin_x86_defs[]`, `cpu_x86_cpuid()`,
  `x86_cpu_expand_features()`, `x86_cpu_filter_features()`,
  `x86_cpu_get_supported_feature_word()` (TCG branch only),
  `x86_cpu_load_model()` and `x86_update_hflags()`. Delete `cpuid.c` and
  `include/cpu/i386/cpuid.h`. Re-add `CPUID_EXT_S2E` on top (see section 8).
- Rename `env->mflags` to `env->eflags`. Upstream's `eflags` has *exactly* S2E's
  `mflags` semantics ("CC flags and DF are set to zero because they are stored
  elsewhere"), so this is a rename, not a redesign, and it removes a
  long-standing divergence.

**Exit:** `x86_64-softmmu` and `i386-softmmu` build clean with `CONFIG_SYMBEX`
off, in both release and debug trees.

### Phase 4: Wire to the KVM shim and boot (2-3 weeks)

- Update libs2e for fields that moved from `CPUX86State` into `CPUState`:
  `jmp_env` (~30 sites), `interrupt_request`, `exception_index`, `halted`,
  `current_tb`, `tlb_table`. Mostly mechanical; `s2e-kvm-vcpu.cpp` and
  `s2e-kvm-state.cpp` carry most of it.
- **Extend the per-state snapshot to the non-cache part of `CPUState`.** Today
  `interrupt_request`, `exception_index`, `halted` and `jmp_env` are saved
  implicitly because they sit inside the snapshotted `CPUX86State` window; once
  they move into the slim `CPUState` they land in the `[&g_cpu, &g_cpu.env)`
  region that `tlb-update.md` registers as shared-concrete and *never
  snapshots*. They are per-state execution state, not caches, so
  `saveConcreteState()` / `restoreConcreteState()` (or a separate registered
  object) must cover them explicitly, or state switches corrupt silently.
- Map libcpu's exit reasons onto `kvm_run` as before; `cpu_x86_exec()` keeps its
  shape, `cpu_exec()` gains upstream's `cpu_exec_setjmp` structure.
- Re-derive `cpu_get_pic_interrupt()`, `do_cpu_init()`, `cpu_state_reset()`
  against the new state layout, including `cpu_init_fp_statuses()`, which must
  run after every reset memset.
- Move the TLB, `se_ram_tlb`, `se_tlb_current` and `tb_jmp_cache` out of the
  snapshotted concrete region, and flush them in `doStateSwitch()` after the new
  state is activated
  and `g_se_disable_tlb_flush` is cleared. Collapse the per-state
  `S2EExecutionStateTlb` into executor-owned data. (Phase 6 work in spirit, but
  the struct layout change belongs here.)
- Rewire libs2e's CPUID plumbing to the new feature model: `S2EKVM::init()`'s
  `x86_cpudef_setup()` + `cpu_x86_register(&m_cpuid, model, is64)` pair becomes
  `x86_cpu_load_model()` +
  `x86_cpu_expand_features()`; `getSupportedCPUID()`'s hardcoded
  `s_cpuid_entries[]` leaf list has to be regenerated to cover leaf 7 subleaves,
  leaf 0xD subleaves, 0x24 and the extended leaves; the per-target
  `nent == 15` (x86-64) / `nent == 21` (i386) build-mismatch guards in
  `setCPUID2()` have to be re-derived from the new counts; and `setCPUID2()`
  should apply the guest-requested mask across all feature words instead of only
  MMX/SSE/SSE2 in leaf 1.
- Rebuild the concrete `testsuite/` baseline.

**Exit:** a Linux guest image boots to a shell under `x86_64-softmmu` and
`i386-softmmu`, and the concrete testsuite passes. Phases 0-4 exist to reach
this milestone.

### Phase 5: Re-implant the S2E instrumentation (2-3 weeks)

The 40-odd `g_sqi.events.*` call sites in the old `translate.c` have to be
re-placed in upstream's decoder, which is structured completely differently: a
table-driven `decode-new.c.inc` feeding `emit.c.inc`, under `translator_loop()`.
Instruction-start/end hooks land naturally on `translator_loop`'s per-insn
callbacks; block start/end and complete on `tb_start` / `tb_stop`. The ones that
need real thought are the instruction-shape hooks (jump start, indirect CTI
start, LEA-RIP-relative, and the special-instruction hook for
`RDTSC`/`SYSENTER`/`SYSCALL`/`PUSHIM`), because they were written against the old
hand-rolled decoder's control flow. Budget for reading the new decoder properly
rather than pattern-matching the old hooks onto it.

**Exit:** core-plugin events fire with the same semantics as before, verified
against a recorded trace from the pre-port build.

### Phase 6: Symbolic execution back on top (4-6 weeks)

- Reintroduce the `RR_cpu` / `WR_cpu` discipline across the imported helper
  sources mechanically, with a checker that fails the build on a direct
  `env->field` access inside a helper translation unit.
- Re-add the symbolic softmmu: the `TLB_SYMB` / `TLB_NOT_OURS` / `TLB_MEM_TRACE`
  paths, `objectState` plumbing, and `g_sqi.mem.*` hooks, now inside upstream's
  `do_ld_mmu` / `do_st_mmu` rather than `softmmu_template.h`.
- Rebuild the bitcode target. `op_helper.c` was one translation unit compiled to
  `op_helper.bc`; upstream's helpers are twelve files, so either `llvm-link` them
  all or add a unity `.c` that includes them. Note the ld/st helper names
  changed upstream (the 32-bit load is `helper_ldul_mmu`); the KLEE-side
  handlers and handler tables must follow.
- Check `tcg-llvm.cpp`'s opcode switch against 11.1's `tcg-opc.h`, and re-verify
  the `se_addend` / `fast_concrete_invocation` invariants end to end. Keep in
  mind `se_addend` is a native-execution concern only: the bitcode softmmu path
  is compiled with `SYMBEX_LLVM_LIB` and reads the plain `addend`, and the
  backend emits the `se_addend` load only under `CONFIG_SYMBEX_MP`.

**Exit:** `{i386,x86_64}-s2e-softmmu` and `-s2e_sp-softmmu` build and pass the
full testsuite, including `basic4-xmm`.


## 7. Symbex constraints to honor during the concrete phases

Symbolic execution comes last, but four of its invariants constrain decisions
taken in phases 1-3. Getting them wrong means redoing that work.

**The CPU state has a symbolic prefix.** Everything before
`offsetof(CPUX86State, eip)` may hold symbolic data; everything after it may not.
`__RR_env_dyn` asserts on exactly that boundary. Upstream's field order is
different (`regs`, `eip`, `eflags`, `cc_*`, segments, ..., with
`ZMMReg xmm_regs[]` far down). When writing the new `CPUX86State` in phase 3,
keep the S2E order (GPRs, `cc_op`/`cc_src`/`cc_dst`/`cc_tmp`, FPU, MMX/XMM,
*then* `eip` and everything concrete), and leave a comment saying why. Rewriting
this later means re-auditing every helper. Note that 11.1 sizes the register
files for APX (`regs[CPU_NB_EREGS]`, 32 GPRs, and `xmm_regs[CPU_NB_EREGS]`),
so the symbolic prefix is larger than the old layout suggests; size the KLEE
objects from `offsetof`, never from carried-over constants.

**Fields must be addressable by `(offset, size)`.** `RR_cpu` / `WR_cpu` are built
on `offsetof` and `sizeof`, so no bitfields anywhere in the symbolic prefix. This
is already why `float_status.float_rounding_mode` is a plain field in libtcg
rather than upstream's bitfield; the same rule applies to anything new that lands
in `CPUX86State`.

**Helper code must be compilable to bitcode as one unit.** Whatever file
organization phase 3 lands on, the helper set has to reach a single
`op_helper.bc`. Keep the helper translation units free of anything that will not
survive `clang -emit-llvm` and `llvm-link` against `softfloat.bc`: no inline asm,
no host intrinsics in a helper path, nothing pulled in from the KVM shim.

**The TLB entry is shared with the code generator.** libtcg's x86_64 backend
emits a load from `offsetof(CPUTLBEntry, se_addend)` on the TLB hit path, sized by
`CPU_TLB_ENTRY_BITS`. Any change to `CPUTLBEntry` in phase 2 has to move in
lock-step with `libtcg/include/tcg/tlb.h` and the `TCGContext` geometry fields,
and the `QEMU_BUILD_BUG_ON` on entry size has to keep holding.


## 8. Failure modes

**Never replace `RR_cpu` / `WR_cpu` with direct struct access to silence a
compiler error.** Under `CONFIG_SYMBEX` those route through
`g_sqi.regs.read_concrete()` when `fast_concrete_invocation` is false, that is,
when the helper is running as bitcode inside KLEE. Direct access reads the native
copy of the CPU state instead of KLEE's, silently, on exactly the paths that
matter. If upstream makes a field unaddressable, change the field.

**Softfloat initialization builds clean and aborts later.** Softfloat asserts at
run time when a NaN-propagation rule or default-NaN pattern was never set, and
`cpu_state_reset()` memsets the CPU state. Anything of that kind must be
reapplied after every reset; `cpu_init_fp_statuses()` in `helper.c` exists for
this reason. When phase 3 imports upstream's initialization, grep for setters the
new reset path does not call.

**Two components, one struct.** `libtcg/include/tcg/tb.h` defines
`TranslationBlock` but `libcpu/include/cpu/tb.h` also declares TB functions, and
libtcg's copy has drifted from upstream. The `tb-maint.c` import in phase 2 will
expose this immediately. Decide the ownership boundary explicitly rather than
patching both.

**`precise-pc.c` is not S2E-original either.** It carries copies of upstream
`translate-all.c`'s restore machinery (`encode_sleb128`, `encode_search`,
`cpu_restore_state_from_tb`) plus the S2E-only `tb_get_instruction_size()`, and
it calls `restore_state_to_opc()`, defined today in `target-i386/translate.c`,
which phase 3 replaces, and reached in 11.1 through
`TCGCPUOps.restore_state_to_opc`. The phase 2 `translate-all.c` import collides
with it exactly the way `tb-maint.c` collides with `tb.h`; decide its ownership
there, not after the frontend lands.

**Target-specific code in a target-independent library.** libtcg currently ships
the i386 helper list and SSE header. Any plan that leaves them there will hit a
circular dependency the moment upstream's helper signatures arrive, because
`HELPER_H` is resolved inside libtcg's `helper-gen.h`. Move it in phase 3, before
importing the helpers, not after.

**`CPUID_EXT_S2E` has to be re-added by hand.** S2E advertises itself to the
guest through bit 16 of `CPUID.01H:ECX`, which upstream leaves reserved. The
bit is free, but nothing in upstream's `feature_word_info[]` will carry it. Add
it as an explicit, commented S2E deviation when importing the feature model in
phase 3, and make sure `x86_cpu_filter_features()` does not mask it off.

**Codegen and C must agree on the `CPUTLBDescFast` index convention.** Upstream
inverts it (`mmuidx_to_fast_index()` = `NB_MMU_MODES - 1 - mmu_idx`); libtcg's
`tlb_mask_table_ofs()` does not. S2E already deviates by placing the TLB at a
positive offset from `env`, so either convention works. But if the generated
code and `cputlb.c` disagree, the fast path reads another mode's table, which
compiles clean and is wrong at run time.

**Softfloat and decoder changes are guest-visible.** Fifteen years of x86 errata
fixes, denormal handling and rounding corrections are all in scope. Existing
guest images and any recorded traces should be re-baselined at phase 4 rather
than diffed against the old build.

## 9. The new TLB in detail

Decision 3.3 says "adopt upstream's TLB wholesale". That is still the
recommendation, but the TLB changed more between 1.0 and 11.1 than any other
part of accel/tcg, and three of the changes interact with S2E in ways that are
not obvious. This section is the detail behind that decision.

### 9.1 What actually changed

| | libcpu (QEMU 1.0) | QEMU 11.1 |
|---|---|---|
| Size | fixed, `CPU_TLB_SIZE` = 1024 | dynamic, 2^6 .. 2^20 entries, resized on flush |
| Entry | one struct, 64 B (S2E) / 32 B | split: `CPUTLBEntry` (32 B fast) + `CPUTLBEntryFull` (~48 B slow) |
| Victim TLB | none | 8 entries per mmu_idx, swapped into the main table on hit |
| Flag bits | `TARGET_PAGE_BITS-1 .. -7`, all in the entry | fixed bits 6-8 in the entry, plus `slow_flags[3]` in `CPUTLBEntryFull` |
| Large pages | `tlb_flush_addr` / `tlb_flush_mask` in env | `large_page_addr` / `large_page_mask` per `CPUTLBDesc` |
| MMU modes | 2 (kernel, user) | `NB_MMU_MODES` = 22 declared; x86 uses 8 |
| Storage | inline in `CPUX86State` | heap, via `fast->table` / `desc->fulltlb` |

Two changes look like problems but are not:

**Huge pages are a non-issue.** TLB entries are `TARGET_PAGE_SIZE` granular in
11.1 exactly as they were in 1.0. `tlb_set_page_full()` stores
`addr & TARGET_PAGE_MASK` and an addend computed at 4K granularity; a 2 MB guest
mapping produces up to 512 separate 4K entries as they are touched.
`full->lg_page_size` and `tlb_add_large_page()` exist only so that
`tlb_flush_range_locked()` can escalate to a full flush when an invalidated
range overlaps a region that large pages were mapped into, the same mechanism
libcpu's `tlb_add_large_page()` already uses with `env->tlb_flush_addr`.
**The `SE_RAM_OBJECT_BITS == 12` invariant is untouched**: one KLEE memory
object still corresponds to one 4K page, and nothing in the new code maps a TLB
entry to more than 4K.

**Dynamic sizing is already supported by the generated code.** libtcg's
x86_64 backend loads `mask` and `table` out of `CPUTLBDescFast` at run time
(`tlb_mask_table_ofs()`), so a changing table size needs no codegen change.
`tcg_ctx->cpu_tlb_size` is vestigial, like every `TCGContext` geometry field
except `tlb_fast_offset` (see 3.3).

### 9.2 Where it collides with S2E

S2E does not treat the TLB as a pure cache. `S2EExecutionStateTlb` keeps
`m_tlbMap`: a map from KLEE `ObjectState` to the list of `(mmu_idx, index)`
coordinates of every TLB entry that points at it, so that when an object is
copied on write (a fork, or a concrete-to-symbolic transition), every cached
`se_addend` and `objectState` can be patched. Three of the 11.1 changes break
that.

**(a) The victim TLB moves entries behind S2E's back.** `victim_tlb_hit()`
*swaps* a main-table entry with a victim entry, and `tlb_set_page_full()`
*evicts* the old main entry into the victim table. Both carry `objectState` and
`se_addend` with them. `m_tlbMap` coordinates address only the main table, so
after either operation the recorded coordinate points at a slot that no longer
holds that object, and `updateTlb()` will patch the wrong entry. This fails
silently; `audit()` would catch it, but it is debug-only.

**(b) Resizing invalidates every coordinate.** `tlb_mmu_resize_locked()` does
`g_free(fast->table); g_free(desc->fulltlb)` and allocates fresh arrays; there
is no rehash. Every index in `m_tlbMap` becomes meaningless. This one is nearly
self-correcting, because resizing only ever happens inside
`tlb_flush_one_mmuidx_locked()`, and a flush already drives
`g_sqi.tlb.flush_tlb_cache()` (skipped in single-path mode, where the map is
unused, and while `g_se_disable_tlb_flush` is set, when flushes do not run at
all). But the flush is now *per mmu_idx*
(`tlb_flush_by_mmuidx()`), whereas `flushTlbCache()` clears the whole map, so
the hook needs either per-index granularity or a documented decision to be
conservative. x86 in 11.1 only uses a partial flush in two places, both
`tlb_flush_by_mmuidx(cs, 1 << MMU_NESTED_IDX)` in `svm_helper.c`, so the
conservative option is cheap.

**(c) Heap tables are not part of the state snapshot.** This collision is the
most involved of the three. S2E registers exactly two KLEE objects over the CPU
state: `[0, offsetof(CPUX86State, eip))` symbolic and
`[offsetof(eip), sizeof(CPUX86State))` concrete. The TLB is inside the second
one *because it is inline in the struct*. That object is registered
shared-concrete, so KLEE never copies it; what gives every execution state its
own TLB with its own `objectState` pointers is the explicit
`saveConcreteState()` / `restoreConcreteState()` memcpy, which is correct by an
explicit ~216 KB copy per state switch rather than by construction. Move the
tables to the heap as upstream does, and all states share one TLB: state A's
`se_addend` would point into state A's concrete buffer while state B runs. That
is only a problem if the TLB survives the switch; section 9.3 argues it should
not.

Three smaller collisions:

**Flag bits.** 11.1 fixed the fast-path flags at bits 6, 7 and 8
(`TLB_INVALID_MASK`, `TLB_NOTDIRTY`, `TLB_FORCE_SLOW`) and documents bits [9:6]
as the whole budget, leaving one free bit. S2E needs three: `TLB_SYMB`,
`TLB_NOT_OURS`, `TLB_MEM_TRACE`, currently at `TARGET_PAGE_BITS-5/-6/-7` where
they now collide with `TLB_NOTDIRTY` and `TLB_INVALID_MASK`. Note that libtcg's
`include/tcg/tlb.h` is an S2E-original that was never brought forward, so it
still describes the pre-11.1 scheme. It even retains `TLB_RECHECK` (removed
upstream in 4.1) and omits `TLB_MEM_TRACE` from `TLB_FLAGS_MASK`, which is why
every consumer hand-masks that bit. This has to be fixed regardless.

**`mmuidx_to_fast_index()`.** Upstream inverts the `f[]` array index
(`NB_MMU_MODES - 1 - mmu_idx`) so lower mmu indices sit closer to `env`.
libtcg's `tlb_mask_table_ofs()` is *not* inverted. Since S2E puts the TLB at a
positive offset from `env` rather than upstream's negative one, it already
deviates. But codegen and C code must agree on the convention, or the fast path
will read another mode's table, which compiles clean and is wrong at run time.

**`CPU_TLB_SIZE` as a compile-time constant.** It is baked into ten places in
libs2ecore: four outside the TLB code itself (`ExprInterface.cpp:184`,
`MMUFunctionHandlers.cpp:232` and `:458`, which re-implement the softmmu fast
path on the KLEE side, and `S2EExecutionState.cpp:833`), and six inside
`S2EExecutionStateTlb.cpp` (`updateRamTlb`, `updateTlbEntry`,
`updateTlbEntryConcreteStatus`, `clearRamTlb`, `clearTlbOwnership`, `audit`).
Three of the four outside sites index `se_ram_tlb`, not the main TLB. The
RAM TLB has no `CPUTLBDescFast`, so the run-time mask read prescribed in 9.3
does not apply to them; the RAM TLB keeps its own pinned size.

### 9.3 Recommendation: take the TLB out of the execution state

The TLB is a cache of a mapping that is fully derivable from the guest page
tables and the KLEE address space. It is in the execution state only because it
happens to be inline in `CPUX86State`. Take it out, heap-allocate it as upstream
does, and **flush it on every state switch**.

The objection is that state switches are frequent and a flush costs refills.
Set against what a state switch already does, that cost is small:

| Already happens on every state switch | Cost |
|---|---|
| `s2e_kvm_flush_disk()` | drain + flush all block devices |
| `s2e_kvm_save_device_state()` -> `kvm_dev_save_snapshot()` | full vmstate serialize of the machine |
| `s2e_kvm_restore_device_state()` -> `kvm_dev_restore_snapshot()` | full vmstate deserialize |
| `FlushTBsOnStateSwitch` (**default true**) -> `se_tb_safe_flush()` | **the entire translation cache is discarded and every block retranslated** |
| `saveConcreteState` / `restoreConcreteState` | ~216 KB memcpy (see below) |

A TB flush forces retranslation of every block that executes afterwards, at tens
of microseconds each across a working set of thousands of blocks. A TLB flush
costs one page-table walk per page actually touched afterwards. The TLB is
already the cheapest of the caches discarded at a switch, so keeping it
per-state saves little.

**What this buys.**

*`cputlb.c` imports nearly unpatched.* The one contained deviation remains the
pinned size (or fixed arena) in `tlb_mmu_init` / `tlb_mmu_resize_locked` plus
`tlb-bounds.h`, because the TLB stays KLEE-visible and bindings cannot be
re-created per state (decision 3.3, `tlb-update.md` section 5). Collisions (b)
and (c) from 9.2 disappear outright: (c) because heap tables not being in the
snapshot is now the intended behavior, and (b) because a resize only ever
happens inside a flush, and a flush already clears `m_tlbMap`.

*Per-state memory drops sharply.* The concrete region carries, per state:

| Field | Bytes |
|---|---:|
| `_tlb_table[2][1024]` @ 64 B | 128 KB |
| `iotlb[2][1024]` @ 8 B | 16 KB |
| `iotlb_ramaddr[2][1024]` @ 8 B (`CONFIG_SYMBEX_MP`) | 16 KB |
| `se_ram_tlb[1024]` @ 24 B | 24 KB |
| `tb_jmp_cache[4096]` @ 8 B | 32 KB |
| **total pure cache** | **~216 KB** |

The TLB changes constantly, so copy-on-write never shares it between states:
that is ~216 KB of live memory per state today, and it would have been ~1 MB
per state at upstream's 8 mmu modes. At a thousand live states that is the
difference between ~200 MB and ~1 GB of cache nobody reads across a switch.

*State switches get faster, not slower.* The `saveConcreteState` /
`restoreConcreteState` memcpy shrinks from ~216 KB to a few KB.

**What it requires.**

- Flush the TLB, the RAM TLB and `m_tlbMap` on state switch. Placement matters:
  `doStateSwitch()` sets `g_se_disable_tlb_flush = 1` for the duration precisely
  to suppress flushes during save/restore, so the flush belongs after the new
  state is activated and the guard is cleared.
- `m_tlbMap` becomes executor data rather than state data. Today that is *not*
  true: `S2EExecutionState`'s copy constructor does `m_tlb = state.m_tlb`,
  handing every forked child a populated map, and `doStateSwitch()` leaves the
  suspended state's map intact (coherent, because inactive maps index the
  snapshot buffer via `getCpuState()`). Once the flush-on-switch lands and
  `clone()` stops copying the map, it is only ever non-empty for the active
  state and the per-state `S2EExecutionStateTlb` collapses into a single
  instance.
- The compile-time `CPU_TLB_SIZE` sites in libs2ecore that index the *main* TLB
  must read the mask at run time
  (`cpu_tlb_fast(cpu, mmu_idx)->mask >> CPU_TLB_ENTRY_BITS`). The `se_ram_tlb`
  sites are excluded: the RAM TLB has no `CPUTLBDescFast` and keeps its pinned
  size (see 9.2). With the pinned-size option the rewrite is optional; it
  becomes mandatory only with the arena option.
- `se_ram_tlb` and `tb_jmp_cache` move out of the snapshot on the same argument.
  11.1 already holds `tb_jmp_cache` as a heap pointer in `CPUState`, and since
  TBs are flushed on switch anyway, its contents are already worthless across
  one.
- `clearTlbOwnership()` at fork stays. The forking state keeps executing with a
  live TLB whose entries are now shared, so the `TLB_NOT_OURS` sweep is still
  needed; only the cross-switch persistence goes away.

**Why it is sound.** The TLB caches (guest page tables -> host address, KLEE
`ObjectState`). Both inputs are per-state, so a cache that is never consulted
across a state boundary cannot leak one state's mapping into another. Verified:
no plugin reads `env->tlb_table`; every reader is an execution fast path in
libs2ecore (`MMUFunctionHandlers.cpp`, `ExprInterface.cpp`,
`S2EExecutionState.cpp`). One plugin *mutates* it: `MergingSearcher` calls
`tlb_flush(env, 1)` before merging. Once the TLB no longer persists across
switches, that call is dead and should be removed with this change.

**Residual risk.** `flush-tbs-on-state-switch` can be set to false, at which
point the TLB flush becomes a larger share of the per-switch cost. Device-state
save/restore still dominates, and that option is documented as "faster but
possibly incorrect", so this does not change the recommendation.

### 9.4 The victim TLB is a separate question

Collision (a) is orthogonal to all of the above: `m_tlbMap` is needed *within* a
single state's execution to patch entries when an `ObjectState` is copied on
write, and the victim TLB moves entries around inside that execution. Making the
TLB non-persistent does not help.

Start with the victim TLB disabled, skipping the eviction in
`tlb_set_page_full()` and the swap in `victim_tlb_hit()`. It is a pure cache;
the cost is extra `tlb_fill` calls.

To enable it later, extend `m_tlbMap`'s coordinate space to address victim slots
(a `(mmu_idx, is_victim, index)` triple rather than a pair, not
`index + n_entries`, since `n_entries` now moves) and add two hooks: a swap for
`victim_tlb_hit()` and a move for the eviction in `tlb_set_page_full()`. Worth
doing only if profiling says the misses matter.

### 9.5 Doing this before the upgrade

The ownership change above is entangled with S2E's state management rather than
with QEMU's code, so it is the part of the port least helped by being done in
the middle of a 43k-line import. It can be landed on the current tree first
(introduce the `ArchCPU` layout, move the caches out of the registered KLEE
region entirely, flush at state switch) and validated on its own, on a tree
that still boots. `tlb-update.md` is that plan; it also shows why upstream's
dynamic sizing needs a pinned size or a fixed arena rather than an
allocator hook.

### 9.6 What still has to be pinned or checked

Nothing about the TLB size remains open. What remains from the earlier
analysis:

- **S2E's flags go in `CPUTLBEntryFull.slow_flags[]`** (bits 5, 6, 7 are free,
  exactly the three S2E needs; `TLB_MMIO` moved into the slow set at bit 4,
  which is why only three remain), driven by `TLB_FORCE_SLOW`. No new fast-path
  bit, no change to `TLB_FLAGS_MASK`, no codegen change. `softmmu_header.h` and
  the KLEE-side handlers change from testing `tlb_entry->addr_read & TLB_SYMB`
  to `full->slow_flags[MMU_DATA_LOAD] & TLB_SYMB`.
- **`se_addend` stays in `CPUTLBEntry`** (the backend loads it inline on the hit
  path); **`objectState` moves to `CPUTLBEntryFull`** (only the helpers read it).
  `CPUTLBEntry` becomes upstream's union, including `addr_idx[]`, whose layout
  `tlb_read_idx()` asserts.
- **`NB_MMU_MODES`**: x86 uses 8 against S2E's 2. This no longer costs snapshot
  bytes, but it still multiplies `tlb_init()` allocations and the
  `clearTlbOwnership` / `audit` sweeps. Declare it as x86's 8 rather than
  inheriting upstream's 22-mode maximum.
- **The `CPUTLBDescFast` index convention** must match between libtcg's
  `tlb_mask_table_ofs()` and upstream's `mmuidx_to_fast_index()`. See section 8.
- **`env->se_tlb_current`** is a cached `CPUTLBEntry *` inside the snapshotted
  state, written by the softmmu IO path and read from bitcode. Once the tables
  are executor-owned it becomes a raw pointer from per-state data into a
  reallocatable array: move it next to the TLB in `CPUNegativeOffsetState`, or
  demote it to an index.
- **`libtcg/include/tcg/tlb.h`** is an S2E-original that was never brought
  forward and still describes the pre-11.1 flag scheme (including `TLB_RECHECK`,
  removed upstream in 4.1, and a `TLB_FLAGS_MASK` that omits `TLB_MEM_TRACE`).
  It has to be fixed regardless of anything else here.
