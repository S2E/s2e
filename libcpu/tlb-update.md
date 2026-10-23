# Making the TLB upgrade-ready, before the upgrade

`PORTING.md` section 9 concludes that the TLB should stop living in the
execution state: it is a cache of a mapping derivable from the guest page tables
and the KLEE address space, and a state switch already discards the whole
translation block cache and round-trips the QEMU device model, both of which
cost far more than refilling it.

That conclusion can be acted on now, on the QEMU-1.0 tree.
It is the one part of the port that is entangled with S2E's state management
rather than with QEMU's code, so it is the part least helped by doing it in the
middle of a 43k-line import. Done first, on a tree that still boots, it can be
validated on its own. Done later, a TLB bug and a `cputlb.c` port bug are hard
to tell apart.

**Scope.** This changes *where the TLB lives and who owns it*. It does not adopt
any of 11.1's TLB algorithms: no dynamic sizing, no victim TLB, no
`CPUTLBEntryFull`, no flag-bit reallocation, no change to `NB_MMU_MODES` or
`CPU_TLB_SIZE`. Those arrive with the import. This work is what makes that
import a drop-in.

Estimated effort: 1.5-2 weeks.

**Status: landed.** Steps 0, 1, 2, 4 and 6 are in the tree. Steps 3 and 5 are
test-only and were not run. The follow-up that section 1 defers to
`PORTING.md` phase 4, moving the per-state execution fields out of
`CPUX86State`, has landed as well: `CPUState` now holds them ahead of the
caches, libs2ecore registers them as a separate snapshotted object, and the
`se_common_start` / `se_common_end` window is gone.


## 1. Target shape

```c
/* libcpu/include/cpu/state.h */

typedef struct CPUTLB {
    CPUTLBDesc     d[NB_MMU_MODES];   /* iotlb today; fulltlb after the import */
    CPUTLBDescFast f[NB_MMU_MODES];
} CPUTLB;

typedef struct CPUNegativeOffsetState {
    CPUTLB tlb;
    CPUTLBRAMEntry se_ram_tlb[CPU_TLB_SIZE];              /* S2E */
    CPUTLBEntry *se_tlb_current;                          /* S2E */
    struct TranslationBlock *tb_jmp_cache[TB_JMP_CACHE_SIZE];
} CPUNegativeOffsetState;

struct CPUState {
    /* ... the ~20 fields accel/tcg actually touches ... */
    CPUNegativeOffsetState neg;       /* MUST BE LAST */
};

struct ArchCPU {
    CPUState    parent_obj;
    CPUX86State env;                  /* immediately after neg */
};
```

One global `ArchCPU`; `env` points at `&g_cpu.env`. Code generation addresses
the TLB at a **negative** offset from `env`, as upstream does:

```c
tcg_ctx->tlb_fast_offset = offsetof(ArchCPU, neg.tlb.f) - offsetof(ArchCPU, env);
```

libtcg needs no change for this: it kept `TCGContext::tlb_fast_offset` as an S2E
deviation (upstream 11.1 dropped the field and computes the offset from
`CPUNegativeOffsetState` directly in `tlb_mask_table_ofs()`), the field is
`int`, and x86 displacements are signed. Keep the `f[]` array **non-inverted**
and define `cpu_tlb_fast(cpu, i)` as `&cpu->neg.tlb.f[i]`; upstream's
`mmuidx_to_fast_index()` inversion is a code-size optimization, and since we
hand-write that header anyway (`PORTING.md` decision 3.1) the deviation costs
one line and a comment. Inverting instead would mean teaching libtcg's
`tlb_mask_table_ofs()` about `NB_MMU_MODES`.

Two KLEE objects over the CPU, as today, plus one for the caches:

| Region | Kind | Snapshotted per state |
|---|---|---|
| `[env, env + offsetof(CPUX86State, eip))` | symbolic | yes (KLEE-managed) |
| `[env + offsetof(eip), env + sizeof(CPUX86State))` | shared concrete | yes (explicit memcpy) |
| `[&g_cpu, &g_cpu.env)`, the caches | shared concrete | **no** |

During this work `CPUState` held *only* the caches. The per-state execution
fields (`interrupt_request`, `exception_index`, `halted`, `jmp_env`, ...)
followed afterwards, and they did not inherit the never-snapshotted region:
`CPUState` is now split at `neg` into a fourth object,
`[&g_cpu, &g_cpu.parent_obj.neg)`, shared concrete and snapshotted by the same
explicit memcpy as the concrete registers, with the caches keeping the row
above.

**The caches must stay KLEE-visible even though they are never snapshotted.**
`use-fast-helpers` defaults to *off*, so `replaceExternalFunctionsWithSpecialHandlers()`
never runs and the special handlers in `MMUFunctionHandlers.cpp` are not
installed. The bodies of `cpu_ld*_kernel` / `cpu_st*_kernel` and
`helper_ld*_mmu` / `helper_st*_mmu` therefore execute as bitcode inside KLEE,
and those bodies contain the inline TLB fast path. It is visible in the
built bitcode: `cpu_ldl_kernel` in `op_helper.bc` loads
`env + offsetof(tlb_table)`, dereferences `.table`, indexes it, reads
`addr_read`, and on a hit reads the plain `addend` at offset 24 before calling
`helper_ldl_mmu` only on a miss. (The bitcode build defines `SYMBEX_LLVM_LIB`,
so `softmmu_header.h` selects `addend`, the host RAM address KLEE binds RAM
objects at; `se_addend`, at offset 32, is used only by natively executed code.)
Every one of those is a KLEE memory operation and must resolve to a bound
object.

`isSharedConcrete` is the right kind of registration: `ObjectState::readConcrete8()`
short-circuits to `((uint8_t *) m_address)[offset]`, so KLEE resolves the address
and then reads native memory, with no per-state buffer and no copy-on-write. The
registration is what is needed; the snapshot is not.

## 2. Invariants to establish

- **I1.** After `doStateSwitch()` returns, every TLB entry is invalid,
  `se_ram_tlb` is cleared, `tb_jmp_cache` is cleared, and `m_tlbMap` is empty.
- **I2.** `m_tlbMap` and the live TLB agree at all times, which is what
  `audit()` already checks.
- **I3.** Nothing reads or writes the TLB of an inactive state.
- **I4.** The cache region stays inside a registered shared-concrete KLEE
  object, bound once in the initial state so every state inherits it, and never
  rebound. See section 5 for why "never rebound" is the part that matters.


## 3. Steps

Each step builds and passes the testsuite on its own. Only step 4 changes
behavior.

### Step 0: Baseline and harness (half a day)

- Record testsuite results.
- Promote `audit()` from the `S2E_DEBUG_TLBCACHE` compile-time switch to a
  runtime flag (`--tlb-audit`) so it can be turned on for a whole suite run.

### Step 1: Fix two latent inconsistencies first (half a day)

Both are pre-existing and both start to matter after step 4. Fixing them
against the current layout, where they are still testable, is cheaper than
fixing them afterwards.

- **`S2EExecutionStateTlb` disagrees with itself about which CPU state it
  means.** `flushTlbCachePage()` and `clearRamTlb()` write through the global
  `env`; `updateTlb()`, `updateRamTlb()`, `clearTlbOwnership()` and `audit()`
  go through `m_registers->getCpuState()`, which returns the *snapshot buffer*
  for an inactive state; and `updateTlbEntry()` /
  `updateTlbEntryConcreteStatus()` take `env` as a parameter, with a latent
  mixed-accessor bug: `updateTlbEntry()` indexes its parameter, but the
  `flushTlbCachePage()` it calls clears the global. Route all of them through
  one accessor, a three-way unification rather than a two-way one. The libcpu
  hook `s2e_update_tlb_entry()` keeps its `env` parameter, since that is
  libcpu's interface, but only checks that it names the active state's CPU
  and then calls the parameterless method.
- **`addressSpaceChangeUpdateTlb()` can fire on an inactive state.**
  `AddressSpace::getWriteable()` notifies whichever state owns the address
  space. The merge path runs with `!m_active`, and, in the dominant case, any
  plugin write to guest memory of a *suspended* state
  (`S2EExecutionStateMemory::write()` has no `m_active` guard) lands here too.
  `addressSpaceSymbolicStatusChange()` and `addressSpaceObjectSplit()` are two
  more unguarded entry points into `updateTlb()`.

  Decision: each entry point does two kinds of work, and they split along
  the active/inactive line. Invalidating the per-state `AddressSpaceCache`
  (directly, or through `notifySplit()`) must run on every state, because a
  suspended state whose object was replaced would otherwise hand back the
  stale one when it next runs. The TLB update is only meaningful for the
  active state, but today it must run on inactive states too: the snapshot
  buffer holds object pointers that a copy-on-write in a suspended state has
  to repoint, or the restored TLB dangles. So step 1 changes nothing on the
  TLB path and step 4 adds the guard inside `updateTlb()` / `updateRamTlb()`,
  below the cache invalidation, where it covers all three callers.
  `S2EExecutionStateMemory::write()` stays unguarded: writing to a suspended
  state is legitimate, and the notifications are the bookkeeping it needs.

  One part is a bug already: `addressSpaceSymbolicStatusChange()` calls
  `updateConcreteFastPath()`, which writes globals describing the *active*
  state (the fast-path flag, `generate_llvm`, the clock scaling), for
  whichever state changed. A plugin that makes a suspended state's registers
  symbolic clobbers the active state's flags until the next switch. Guard
  that call with `m_active` in step 1; it is independent of the TLB.

### Step 2: Introduce `ArchCPU`, no ownership change (2-3 days)

- Add `libcpu/include/cpu/state.h` per section 1: `CPUTLB`,
  `CPUNegativeOffsetState`, the slim `CPUState`, `ArchCPU`, `cpu_env()`,
  `env_cpu()`, `cpu_tlb_fast()`.
- Move out of `CPU_COMMON` / `CPU_COMMON_TLB` / `CPU_COMMON_PHYSRAM_TLB`:
  `tlb_table` (already a `CPUTLBDescFast[]` whose `.table` points into the
  inline `_tlb_table` backing store), `_tlb_table`, `iotlb`, `iotlb_ramaddr`,
  `se_ram_tlb`, `tb_jmp_cache`, and `se_tlb_current`, the cached
  `CPUTLBEntry *` the softmmu IO path keeps in the CPU state; it points into
  `_tlb_table` and must move with it.
- `cpu_x86_init()` allocates the single `ArchCPU`.
- Set `tcg_ctx->tlb_fast_offset` to the negative value.
- Rewrite the accessors: about a dozen sites in libcpu (`exec-tlb.c`,
  `softmmu_header.h`, `softmmu_template.h`, `exec.c`, `cpu-exec.c`,
  `translate-all.c`) and five in libs2ecore (`ExprInterface.cpp:187`,
  `MMUFunctionHandlers.cpp:236` and `:461`, `S2EExecutionState.cpp:835`, plus
  the `S2EExecutionStateTlb` loops).
- **Register `[&g_cpu, offsetof(ArchCPU, env))` as its own shared-concrete
  object** in the initial state, alongside the existing two. Keep it snapshotted
  for this step by copying it explicitly, so behavior is unchanged.

Exit: `tlb_fast_offset < 0`, TLB addressed through `cpu_tlb_fast()`, behavior
unchanged, testsuite green.

### Step 3: Confirm the binding is inherited, not per-state (1 day)

The cache object is bound in the initial state's address space and inherited by
every fork. Confirm that, because step 4 depends on it and section 5 depends on
it never changing:

- Add a check that a memory operation resolving into `[&g_cpu, &g_cpu.env)`
  finds the object in *every* state, not just descendants of the initial one.
- Run the suite with both `use-fast-helpers` off (the default, bitcode bodies
  execute) and on (handlers installed, bodies skipped). Both must pass; only the
  first exercises the KLEE-visible TLB path.

Exit: suite green in both modes. The explicit cache save/restore from step 2 is
still in place, so semantics are unchanged.

### Step 4: Stop snapshotting, flush on switch (2-3 days)

This step changes behavior; the earlier ones do not.

- Drop the cache object from `saveConcreteState()` / `restoreConcreteState()`.
- In `doStateSwitch()`, **after** `newState->m_active = true` and **after**
  `g_se_disable_tlb_flush = 0`: `tlb_flush(env, 1)` (which already clears
  `tb_jmp_cache` and, in multi-path mode, drives `g_sqi.tlb.flush_tlb_cache()`,
  always against the *active* state), `clearRamTlb()`, and an explicit
  `m_tlbMap.clear()` on the *outgoing* state, which the hook does not touch.
  Ordering matters, because `tlb_flush()` returns early while the guard is set.
- `updateTlb()` and `updateRamTlb()`: when the state is not active, check
  that `m_tlbMap` is empty and return. Sound, because an inactive state has
  no TLB; it gets one when it is activated. The guard sits below the
  `AddressSpaceCache` invalidation in the three entry points (step 1
  decision), and `S2EExecutionStateTlb` receives the `m_active` pointer the
  way `S2EExecutionStateMemory` does.
- `getCpuCaches()`: drop the per-state buffer branch. It aborts when the state
  is not active and otherwise returns the global region, so every TLB method
  enforces I3 through the one accessor step 1 routed them through.
- Assert `m_tlbMap.empty()` whenever `!m_active`. This needs one edit first:
  `S2EExecutionState`'s copy constructor does `m_tlb = state.m_tlb`, handing
  every forked child the parent's populated map, so `clone()` must clear the
  child's map (or stop copying `m_tlb`) or the assertion fires on the first
  fork. Keeping the class per-state with that assertion is a smaller diff than
  hoisting it to the executor and gives the same guarantee; hoist later if it
  reads better.

Exit: testsuite green.

### Step 5: Test the assumption directly (1 day)

- Add a debug flag that flushes the TLB and `m_tlbMap` before **every** TB
  execution, not just at state switches. If the suite passes with it on, nothing
  anywhere depends on TLB persistence at any granularity, which is the claim
  this change rests on.
- Run the suite with `--tlb-audit` on.

### Step 6: Cleanups this enables (half a day)

- `compareArchitecturalConcreteState()` did two `memcmp`s to skip the
  `se_common_start` .. `se_common_end` window. That window did *not* exist only
  for the caches: it also hid `current_tb`, `jmp_env`, the breakpoint and
  watchpoint list heads, `opaque`, `temp_buf` and friends. With the rest of
  `CPU_COMMON` moved into the slim `CPUState`, the window and the marker
  fields are gone and the comparison is a single `memcmp` over
  `[eip, sizeof(CPUX86State))`.
- State merging becomes strictly more permissive as a side effect: it stops
  comparing cache contents that were never architecturally meaningful. (The
  `tlb_flush(env, 1)` that `MergingSearcher` performs before merging becomes
  dead code at the same time and should be removed here.)


## 4. Hazards

**`flushTlbCachePage()` asserts the object is in `m_tlbMap`.** After step 4 the
map is emptied at every switch, so any path that still expects an entry there
will abort rather than corrupt. That is the behavior we want, but expect to hit
it during bring-up; it is the most likely failure mode of step 4. The assert
is live in every build: libs2e strips `-DNDEBUG` from the release flags.

**The flush must land outside `g_se_disable_tlb_flush`.** `doStateSwitch()` sets
that guard for the duration of save/restore because "some state save/restore
logic flushes the cache" and doing so mid-memory-operation is unsafe. The new
flush belongs after the guard is cleared, at the end of the function.

**`clearTlbOwnership()` at fork stays.** The forking state keeps executing with
a live TLB whose entries are now shared with the child, so the `TLB_NOT_OURS`
sweep is still required. Only cross-switch persistence goes away.

**`registerCpu()` checks `sizeof(*cpuEnv) == cpuEnv->size`**, against
`m_env->size = sizeof(*m_env)` set in libs2e. Both move together, but keep the
check; it is a cheap tripwire for exactly the kind of layout skew this work
introduces.

**Do not assume the special function handlers are installed.**
`replaceExternalFunctionsWithSpecialHandlers()` is guarded by
`if (UseFastHelpers)`, and `use-fast-helpers` defaults to false and is not
enabled by any config in the tree. In the default configuration the bitcode
bodies of `cpu_*_kernel` and `helper_*_mmu` run inside KLEE and read the TLB
through KLEE's memory model. Any reasoning that starts from "the handler
intercepts it" is reasoning about the non-default path.

**S2E snapshots are unaffected.** Guest snapshots are handled by vanilla QEMU,
not by libcpu, so changing `CPUX86State`'s layout does not invalidate existing
images.


## 5. Dynamic sizing, and why it is not an allocator problem

**`malloc`/`free` do not have to be intercepted.** The reason is not that the
TLB is invisible to KLEE; it is visible (section 1). The reason is that the
reallocation should be removed rather than tracked.

Upstream resizes by `g_free(fast->table); g_free(desc->fulltlb)` followed by
`g_try_new` for both, inside `tlb_mmu_resize_locked()`, which is only ever
reached from `tlb_flush_one_mmuidx_locked()`. Both the address and the size
change, and there is no rehash; the caller immediately runs
`tlb_mmu_flush_locked()`.

Tracking that in KLEE would mean unbinding the old object and binding a new one
at each resize. The mechanics are easy: there are exactly three allocation
sites (`tlb_mmu_init`, `tlb_mmu_resize_locked`, `tlb_destroy`), so nothing
generic like an allocator hook is required. The difficulty is in the binding
model:

**KLEE bindings are per-address-space, and address spaces are per-state.**
`ExecutionState::addExternalObject()` calls `m_addressSpace.bindObject()`, so a
binding created at time T exists only in that state and in states forked from it
after T. Every existing S2E registration (the CPU state, RAM, the dirty mask)
is done once in the *initial* state precisely so that every state inherits
it. A TLB rebind at run time would leave every sibling state resolving the TLB
address to nothing, and its next bitcode TLB read would fault.

So the reallocation has to go. Two ways:

**Pin the size (recommended for the port).** Set
`CPU_TLB_DYN_MIN_BITS == CPU_TLB_DYN_DEFAULT_BITS == CPU_TLB_DYN_MAX_BITS` so
`tlb_mmu_resize_locked()` returns on the `new_size == old_size` path it already
has, and point `tlb_mmu_init()` at a statically allocated region instead of
`g_new`. One registration at init, inherited by everyone, never rebound. Two
patched functions plus `tlb-bounds.h`.

**Fixed arena, variable in-use sub-range (the upgrade path).** Register a
maximum-size arena once at init and have `tlb_mmu_init()` /
`tlb_mmu_resize_locked()` hand out slots inside it rather than calling
`g_new`/`g_free`. Dynamic sizing then works exactly as upstream intends and the
KLEE binding never changes. Same two functions patched, so no extra deviation
cost. One caveat to fix first: `ObjectState`'s constructor allocates a
`ConcreteBuffer` of the object's size whenever `size > FAST_CONCRETE_BUFFER_SIZE`,
and `setSharedConcrete()` is only called *afterwards* by
`addExternalObject()`, so today a large arena would allocate a matching buffer
it never uses. Passing the shared-concrete flag into the constructor is a small
KLEE change and a prerequisite for this option, but it must be per-object
opt-in rather than a blanket skip: the existing CPU concrete object *uses* its
`ConcreteBuffer` as the `saveConcreteState()` / `restoreConcreteState()`
snapshot store and must keep it.

Everything else about sizing is already fine:

- **Code generation** needs nothing. libtcg's backend loads `mask` and `table`
  out of `CPUTLBDescFast` at run time; the only compile-time constant on that
  path is `CPU_TLB_ENTRY_BITS`, and the entry size does not change.
- **`m_tlbMap`** coordinates are invalidated by a resize, but a resize only
  happens inside a flush and a flush already clears the map.
- **libs2ecore's index arithmetic**, the compile-time `CPU_TLB_SIZE` uses (ten
  in all; the `se_ram_tlb` ones keep their own pinned size), must become
  run-time mask reads mirroring upstream's `tlb_index()` /
  `tlb_entry()`. Needed for the arena option, not for the pinned one.
- **Cached entry pointers**: one. `m_tlbMap` stores indices and
  `S2EExecutionStateTlb` only takes `CPUTLBEntry *` locally within a call, but
  `env->se_tlb_current` is a live `CPUTLBEntry *` in the CPU state, written by
  the softmmu IO path and read from bitcode. Step 2 moves it next to the
  tables; under the arena option it must be rebased or demoted to an index when
  the in-use sub-range changes.

One thing to check rather than assume if the arena option is ever taken:
`tlb_mmu_resize_locked()` reads `get_clock_realtime()` for its window, so table
size would vary run to run. It is not architectural state and is not
snapshotted, so it cannot change guest-visible behavior. But if bit-for-bit
replay determinism matters, drive the heuristic from an instruction counter
instead.

## 6. What this deliberately leaves alone

Dynamic TLB sizing, the victim TLB, `CPUTLBEntryFull`, the 11.1 flag-bit
allocation, `NB_MMU_MODES`, and `CPU_TLB_SIZE` all stay exactly as they are.
Stopping here keeps the split clean: every one of those is a *QEMU* change that
arrives with `cputlb.c`, whereas everything above is an *S2E* change that would
otherwise have to be debugged simultaneously with a 43k-line import.

After this lands, `PORTING.md` phase 2's TLB work reduces to importing
`cputlb.c` and mapping `CPUTLBEntryFull` onto `MemoryDesc`, with the state
management already in the shape the imported code expects.

That import has landed (`softmmu-update.md`). It brought upstream's
`CPUTLBEntryFull`, flag allocation and dynamic sizing code, with the size
pinned to `CPU_TLB_SIZE` entries and the victim TLB disabled. `NB_MMU_MODES`
is still 2.
