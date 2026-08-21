---
name: upgrade-libtcg
description: Upgrade libtcg and libutils' vendored QEMU code (TCG core, softfloat, host utilities) to a newer QEMU release. Use when asked to move libtcg to a new QEMU version, pull in upstream TCG changes, rebase the TCG fork, or when a QEMU tag is named alongside libtcg/tcg/softfloat/libutils. Covers the normalize-then-merge workflow, the S2E deviations that must survive, and the libcpu fallout.
---

# Upgrading libtcg and libutils to a new QEMU release

Two components carry vendored QEMU code and are upgraded together:

- **libtcg**: a de-QEMU-ified fork of QEMU's TCG (headers moved out of `qemu/`,
  `exec/` and `accel/tcg/` into `tcg/utils/`, `tcg/exec/` and `tcg/accel/`),
  plus `fpu/` and the target-dependent `utils/{bswap.h,cpu-float.h,log.*}`.
- **libutils**: QEMU's platform-independent utilities under `include/utils/`
  and `src/utils/` (upstream `util/`, `include/qemu/`, `host/include/`).

Both trees are reformatted with the S2E `.clang-format`. **`git cherry-pick`
and `patch` never apply**: every line differs because of reformatting alone.

The shared driver lives in `scripts/upgrade/` at the S2E source root; each
component keeps `scripts/upgrade/{BASELINE,mapping.tsv}`. Read
`scripts/upgrade/README.md` first.

## The core idea

Run the upstream file through clang-format with the S2E style *before*
comparing. That collapses the diff to the genuine S2E delta (`libtcg/src/tcg.c`
goes from ~6800 differing lines to ~79), which makes the upgrade an ordinary
three-way merge:

    base   = clang-formatted upstream at the OLD tag
    theirs = clang-formatted upstream at the NEW tag
    ours   = the current S2E file

Expect most files to merge clean, including the big ones (`tcg.c`, `tcg-op.c`,
`optimize.c`, `tcg-target.c.inc`). Conflicts are almost always one hunk in an
include block or where S2E's `extern "C"` guard meets appended upstream code.

## Steps

### 1. Scope it

    cat libtcg/scripts/upgrade/BASELINE libutils/scripts/upgrade/BASELINE
    git -C ~/qemu log --oneline <old>..<new> -- tcg/ include/tcg/ util/ include/qemu/ host/include/

**Neither component is uniformly at one version.** The TCG core, `fpu/` and the
vendored utilities track `BASELINE`, but the hand-written subsets flagged below
the "hand written" marker in each `mapping.tsv` (libutils: `osdep.*`,
`cutils.*`, `bitmap.h`, `memalign.h`; libtcg: `log.*`, `bswap.h`) are still
v8.1.0-era and are not vendored. Before assuming a file's baseline, check it:
format the file at several candidate tags and pick the smallest diff. A file
that is stale relative to its neighbors is a bug waiting to happen: the 11.1
upgrade found `tcg-gvec-desc.h` stranded at an old descriptor encoding while
`simd_desc()` already wrote the new one.

Note deleted, added and renamed files in the upstream range; `merge.sh` reports
them but cannot decide what to do about them.

### 2. Merge, libutils first

    cd scripts/upgrade
    QEMU_SRC=~/qemu ./merge.sh libutils <old-tag> <new-tag>            # dry run
    QEMU_SRC=~/qemu ./merge.sh libutils <old-tag> <new-tag> --apply    # write back
    QEMU_SRC=~/qemu ./merge.sh libtcg   <old-tag> <new-tag>
    QEMU_SRC=~/qemu ./merge.sh libtcg   <old-tag> <new-tag> --apply

libutils goes first because libtcg's merged code may call utility APIs that
only arrive with the libutils merge. Prefer applying a chosen subset by hand
over `--apply` when the upgrade is scoped to part of the tree (e.g. TCG core
but not `fpu/`). Merged output sits in `scripts/upgrade/out/<component>/merged/`.
`--apply` writes conflicted files with markers and lists them; resolve them
before building.

Resolve conflicts by keeping the S2E side of include blocks (the `<tcg/...>` and
`<utils/...>` paths and `// clang-format off` markers), and keeping the upstream
side of everything else, with the `extern "C"` guard moved to wrap the new code.

### 3. Import new files by hand

Files upstream added have no S2E name to merge into. Normalize, then rewrite the
includes to S2E paths and add `extern "C"` guards:

    QEMU_SRC=~/qemu ./normalize.sh <new-tag> include/tcg/foo.h > ../../libtcg/include/tcg/foo.h
    QEMU_SRC=~/qemu ./normalize.sh <new-tag> include/qemu/bar.h > ../../libutils/include/utils/bar.h

Place by dependency, not by origin: anything that reads no `TARGET_*` or
`CONFIG_SYMBEX` macro belongs in libutils (libtcg is built six times per build
type, libutils once). Add the new row to that component's `mapping.tsv`.

**Make imported headers self-contained.** Upstream relies on `qemu/osdep.h`
being included first everywhere; S2E has no such prelude, and the S2E
clang-format sets `SortIncludes: true`, so it will reorder an include block and
break any header that depends on its position. Host configuration macros
(`CONFIG_INT128`, `HOST_BIG_ENDIAN`, `HAVE_GLIB_WITH_SLICE_ALLOCATOR`) come from
`utils/config-host.h`, pulled in by `utils/int128.h` and `utils/osdep.h`; never
add `-D` copies to a CMakeLists.

### 4. Build

    cd ~/s2e/build/libutils-release && make -j16
    cd ~/s2e/build/libs2e-release   && make -j16
    cd ~/s2e/build/libutils-debug   && make -j16
    cd ~/s2e/build/libs2e-debug     && make -j16

libutils before libs2e, since libs2e links `libutils.a`. Both libs2e trees have
six configurations each: `{i386,x86_64}-{,s2e-,s2e_sp-}softmmu`. Iterate on
`libs2e-release/x86_64-s2e-softmmu/libtcg` alone for a fast loop, but finish on
the full build: the i386 (`TARGET_LONG_BITS=32`) configurations exercise
different paths.

### 5. Verify the S2E patches survived

A clean merge is not a correct merge. Diff each changed file against normalized
upstream at the new tag and confirm the residual is *only* the expected S2E
delta:

    diff out/libtcg/new/src/x86_64/tcg-target.c.inc   ../../libtcg/src/x86_64/tcg-target.c.inc
    diff out/libutils/new/include/utils/bitops.h      ../../libutils/include/utils/bitops.h

Patches that must still be there, and that upstream refactors can silently
relocate:

- `s->qemu_ld_helpers` / `s->qemu_st_helpers` (per-context, not the static table)
- the `CONFIG_SYMBEX && CONFIG_SYMBEX_MP` `se_addend` load on the TLB hit path;
  check it is anchored to the right `tcg_out_ld`, not merely present
- `tcg_target_force_tb_exit`
- `tcg_prologue_init(TCGContext *s)` taking the context explicitly
- `mutex_t` / `spin_*` / `g_*cache_linesize` in `region.c`

### 6. Re-normalize and record

    ./run-clang-format.sh          # from the S2E source root
    make -j16                      # formatting can reorder includes; rebuild

Then update both `BASELINE` files and any renamed paths in both `mapping.tsv`,
add newly tracked files, and confirm the trees are normalized by merging the
new tag onto itself:

    QEMU_SRC=~/qemu ./merge.sh libutils <new-tag> <new-tag>    # must be 0 conflicts
    QEMU_SRC=~/qemu ./merge.sh libtcg   <new-tag> <new-tag>    # must be 0 conflicts

### 7. Commit

Per `CLAUDE.md`: `component: short description`, lowercase. Split by phase:
tooling, rename, the libutils merge, the libtcg merge, then each consumer.
Explain *why* in the body, especially for anything that deviates from upstream.

## Deviations that must survive every merge

libutils:

- **`host/generic/atomic128-cas.h`** renames the `new` parameter to `_new`.
  These headers are included from C++, where `new` is a keyword.
- **`utils/bitops.h`** wraps `#define BIT(nr)` in `#ifndef BIT`, because
  `libcpu/include/cpu/kvm.h` also defines it.
- **`utils/osdep.h`** carries what upstream keeps in `include/qemu/compiler.h`
  (`QEMU_FLATTEN`, `QEMU_ALWAYS_INLINE`, `typeof_strip_qual`, ...). When a merge
  pulls in code that needs a new compiler macro, add it here.
- **`utils/int128.h` and `utils/osdep.h`** include `<utils/config-host.h>`.
- **`src/utils/cpuinfo-i386.c`** includes `<utils/cpuid.h>`; `CONFIG_CPUID_H`
  stays undefined on purpose (see `utils/config-host.h`: the TCG op set must
  not grow past what `tcg-llvm.cpp` translates).

libtcg:

- **`float_status.float_rounding_mode` is a plain field, not a bitfield.** S2E
  addresses the CPU state by `(offset, size)`; `RR_cpu`/`WR_cpu` need
  `offsetof`/`sizeof`, which no bitfield supports.
- **`tcg/utils/cpu-float.h`** holds the float/integer reinterpretation unions
  that upstream keeps in `include/qemu/cpu-float.h`. Leaving them in `bswap.h`
  creates a cycle: `softfloat-types.h` -> `registerfields.h` -> `bitops.h` ->
  `host-utils.h` -> `bswap.h`.
- **`accel/getpc.h`** drops upstream's `#ifndef CONFIG_TCG #error` guard.
- **`exec/helper-head.h.inc`** keeps its `#ifdef TARGET_LONG_BITS` guard instead
  of including `exec/target_long.h`.

## The libcpu fallout

libcpu consumes libtcg and libutils and breaks in ways their own builds will
not catch.

**Never replace `RR_cpu`/`WR_cpu` with direct struct access to silence a
compiler error.** Under `CONFIG_SYMBEX` these route through
`g_sqi.regs.read_concrete()` when `fast_concrete_invocation` is false, that is,
when the helper runs as bitcode inside KLEE. Direct access reads the native copy
of the CPU state instead of KLEE's, silently, on exactly the symbolic paths that
matter. If upstream makes a field unaddressable, change the field in libtcg.

**Check for newly required initialization.** Softfloat asserts at runtime when a
NaN propagation rule or default NaN pattern was never set. `cpu_state_reset()`
memsets the CPU state, so anything of that kind must be reapplied there; see
`cpu_init_fp_statuses()` in `libcpu/src/target-i386/helper.c`, mirroring QEMU's
`target/i386/tcg/fpu_helper.c`. This class of bug builds clean and aborts later,
so grep upstream's target code for setters the fork does not call.

**Watch for removed macros and renamed flags**, e.g. the removal of
`TARGET_INSN_START_EXTRA_WORDS` (which made `tcg_gen_insn_start` take a fixed
`INSN_START_WORDS` arguments, callers padding with zeroes), and
`float_flag_input_denormal` -> `float_flag_input_denormal_flushed`.

## Things that change behavior, not just code

Say so explicitly when reporting the upgrade:

- Softfloat changes are guest-visible, and `softfloat.c` is compiled to
  `softfloat.bc` and interpreted by KLEE, so symbolic paths see them too.
- `float_status` layout changes do not break compatibility with existing S2E
  snapshots. Snapshots are handled by vanilla QEMU.
- `tcg-llvm.cpp` switches over TCG opcodes; if the upstream range removes or
  renames any, the LLVM translator needs updating. Check the opcode list diff:
  `diff <(git show <old>:include/tcg/tcg-opc.h | grep -oE '^DEF\([a-z0-9_]+') ...`

## Testing

`testsuite/` drives real guest images through `~/s2e/projects/testsuite/*`. The
launch scripts use `BUILD=debug`, so build `libs2e-debug` before running.
`basic4-xmm` is the one most likely to notice softfloat changes. Ask before
running the suite; it is slow, and the user often has it covered.
