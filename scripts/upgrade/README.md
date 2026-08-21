# Upgrading vendored QEMU code to a new QEMU release

Two S2E components carry code vendored from QEMU:

- **libtcg** is a fork of QEMU's TCG, de-QEMU-ified (headers moved out of
  `qemu/`, `exec/` and `accel/tcg/` into `tcg/utils/`, `tcg/exec/` and
  `tcg/accel/`) and reformatted with the S2E `.clang-format` style. It also
  carries `fpu/` (softfloat) and the three target-dependent utilities
  `utils/bswap.h`, `utils/cpu-float.h` and `utils/log.*`.
- **libutils** carries QEMU's platform-independent utilities under
  `include/utils/` and `src/utils/` (`util/`, `include/qemu/` and
  `host/include/` upstream). They moved out of libtcg because they depend on no
  target macro, and libtcg is configured once per target, so keeping them there
  compiled every object six times per build type.

A plain `git cherry-pick` or `patch` against upstream never applies to either:
every line differs because of reformatting alone. The trick that makes upgrades
tractable is to *normalize the formatting first*. Running an upstream file
through `clang-format` with the S2E style reduces the difference against its
S2E counterpart to the genuine S2E delta. For `libtcg/src/tcg.c` that is the
difference between a 6800-line diff and a 79-line one.

The upgrade is then an ordinary three-way merge:

    base    = clang-formatted upstream file at the OLD tag
    theirs  = clang-formatted upstream file at the NEW tag
    ours    = the current S2E file

    git merge-file ours base theirs

## Files

The driver lives here and is shared. Each component keeps its own data under
`<component>/scripts/upgrade/`:

- `normalize.sh` (here): extract one file from a QEMU tag and clang-format it.
- `merge.sh` (here): normalize every mapped file of one component at both tags
  and three-way merge. Output goes to `scripts/upgrade/out/<component>/`.
- `<component>/scripts/upgrade/mapping.tsv`: component path -> upstream QEMU
  path, one pair per line, tab separated. Only files that track upstream are
  listed; S2E-original files are deliberately absent. A `# upstream-dirs:`
  header names the upstream directories the component draws from, which
  `merge.sh` scans for files added since the old tag.
- `<component>/scripts/upgrade/BASELINE`: the QEMU tag `mapping.tsv` paths and
  the current tree correspond to. Update it (and any renamed paths in
  `mapping.tsv`) once an upgrade lands.

## Running an upgrade

    export QEMU_SRC=~/qemu
    ./merge.sh libutils v10.2.0 v11.1.0            # dry run, reports conflicts
    ./merge.sh libtcg   v10.2.0 v11.1.0
    ./merge.sh libtcg   v10.2.0 v11.1.0 --apply    # same, but writes back into the tree

A QEMU tag bump always covers both components: libtcg's merged code may call
utility APIs that only arrive with the libutils merge. Run libutils first.

`merge.sh` resolves upstream renames with the rename limit lifted (`git diff
-M -l0`), and reports every row that changed upstream or was renamed. A pure
rename is reported even when the content did not change, because its
`mapping.tsv` row has to be updated. Files deleted upstream, files added since
the old tag, and mapping rows whose S2E file is missing are reported too; all
of those need a human decision. `--apply` writes conflicted files with their
conflict markers and lists them at the end, so the tree does not build until
they are resolved.

## Hand-written subsets

Not every file tracks upstream closely. The rows below the "hand written"
marker in each `mapping.tsv` are heavily reduced S2E-specific subsets rather
than vendored copies, and are still v8.1.0-era. They are listed for reference
but want a manual look rather than a mechanical merge:

- libutils: `utils/memalign.h`, `utils/bitmap.h`, `utils/cutils.{h,c}`,
  `utils/osdep.{h,c}`.
- libtcg: `utils/bswap.h`, `utils/log.{h,c}`.

## Deviations that must survive every merge

### libutils

- `host/generic/atomic128-cas.h` renames the `new` parameter to `_new`, since
  these headers are included from C++.
- `utils/bitops.h` wraps `#define BIT(nr)` in `#ifndef BIT`, because
  `libcpu/include/cpu/kvm.h` also defines it.
- `utils/osdep.h` carries what upstream keeps in `include/qemu/compiler.h`
  (`QEMU_FLATTEN`, `QEMU_ALWAYS_INLINE`, `typeof_strip_qual`, ...). When a merge
  pulls in code that needs a new compiler macro, add it here.
- `utils/int128.h` and `utils/osdep.h` include `<utils/config-host.h>`, the
  S2E-original header that defines `CONFIG_INT128`, `HOST_BIG_ENDIAN` and
  `HAVE_GLIB_WITH_SLICE_ALLOCATOR` from compiler builtins. Upstream gets them
  from meson through `qemu/osdep.h`; here the header is what keeps every
  translation unit, in every component, on the same definitions.
- `src/utils/cpuinfo-i386.c` includes `<utils/cpuid.h>` where upstream
  includes `qemu/cpuid.h`, and `CONFIG_CPUID_H` stays undefined on purpose; see
  `utils/config-host.h`.

### libtcg

- `float_status.float_rounding_mode` is a plain field rather than a bitfield.
  S2E addresses the CPU state by (offset, size) so helpers running as bitcode
  inside KLEE can read it back, which `offsetof`/`sizeof` on a bitfield cannot
  express.
- `utils/cpu-float.h` holds the float/integer reinterpretation unions that
  upstream keeps in `include/qemu/cpu-float.h`. Leaving them in `bswap.h`, as
  older libtcg did, creates an include cycle through `softfloat-types.h` ->
  `registerfields.h` -> `bitops.h` -> `host-utils.h` -> `bswap.h`.
- `accel/getpc.h` drops upstream's `#ifndef CONFIG_TCG #error` guard.
- `exec/helper-head.h.inc` keeps its `#ifdef TARGET_LONG_BITS` guard instead of
  including `exec/target_long.h`.

## After merging

Re-run `run-clang-format.sh` from the S2E source root so the tree stays
normalized for the next upgrade, update each component's `BASELINE`, and
confirm normalization by merging the new tag onto itself:

    ./merge.sh libutils <new-tag> <new-tag>    # must be 0 conflicts
    ./merge.sh libtcg   <new-tag> <new-tag>    # must be 0 conflicts
