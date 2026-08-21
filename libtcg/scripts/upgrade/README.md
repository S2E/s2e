# Upgrading libtcg to a new QEMU release

libtcg is a fork of QEMU's TCG that has been de-QEMU-ified (headers moved out of
`qemu/`, `exec/` and `accel/tcg/` into `tcg/utils/`, `tcg/exec/` and
`tcg/accel/`) and reformatted with the S2E `.clang-format` style. A plain
`git cherry-pick` or `patch` against upstream therefore never applies: every
line differs because of reformatting alone.

Most of what used to sit in `tcg/utils/` now lives in libutils under
`utils/`, with its own copy of this tooling in `libutils/scripts/upgrade/`.
Only `utils/bswap.h`, `utils/cpu-float.h` and `utils/log.*` stayed here: the
first two depend on the target and on the softfloat types, and `log.c` tests
`TARGET_I386` and `CONFIG_SYMBEX` to build its mask table. Bumping a QEMU tag
means running both components' `merge.sh`.

The trick that makes upgrades tractable is to *normalize the formatting first*.
Running an upstream file through `clang-format` with the S2E style reduces the
difference against its libtcg counterpart to the genuine S2E delta. For
`src/tcg.c` that is the difference between a 6800-line diff and a 79-line one.

The upgrade is then an ordinary three-way merge:

    base    = clang-formatted upstream file at the OLD tag
    theirs  = clang-formatted upstream file at the NEW tag
    ours    = the current libtcg file

    git merge-file ours base theirs

## Files

- `mapping.tsv` — libtcg path -> upstream QEMU path, one pair per line, tab
  separated. Only files that track upstream are listed; S2E-original files
  (`tcg-s2e.c`, `tcg-llvm.cpp`, `tb.h`, `tlb.h`, ...) are deliberately absent.
- `BASELINE` — the QEMU tag `mapping.tsv` paths and the current tree correspond
  to. Update it (and any renamed paths in `mapping.tsv`) once an upgrade lands.
- `normalize.sh` — extract one file from a QEMU tag and clang-format it.
- `merge.sh` — normalize every mapped file at both tags and three-way merge.

## Running an upgrade

    export QEMU_SRC=~/qemu
    ./merge.sh v10.2.0 v11.1.0            # writes into ./out, reports conflicts
    ./merge.sh v10.2.0 v11.1.0 --apply    # same, but writes back into the tree

`merge.sh` follows upstream renames automatically (via `git diff -M`) and
reports files that were deleted upstream or added since the old tag, both of
which need a human decision.

Not every libtcg file tracks upstream closely. The utility files below the
"hand written" marker in `mapping.tsv` (`utils/log.*`, `utils/bswap.h`) are
heavily reduced S2E-specific subsets rather than vendored copies, and are still
v8.1.0-era. They are listed for reference but want a manual look rather than a
mechanical merge.

Several S2E deviations in the merged code are deliberate and must survive future
merges:

- `float_status.float_rounding_mode` is a plain field rather than a bitfield.
  S2E addresses the CPU state by (offset, size) so helpers running as bitcode
  inside KLEE can read it back, which `offsetof`/`sizeof` on a bitfield cannot
  express.
- `utils/cpu-float.h` holds the float/integer reinterpretation unions that
  upstream keeps in `include/qemu/cpu-float.h`. Leaving them in `bswap.h`, as
  older libtcg did, creates an include cycle through `softfloat-types.h` ->
  `registerfields.h` -> `bitops.h` -> `host-utils.h` -> `bswap.h`.

## After merging

Re-run `run-clang-format.sh` from the S2E source root so the tree stays
normalized for the next upgrade.
