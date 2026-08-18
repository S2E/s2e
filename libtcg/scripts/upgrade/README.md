# Upgrading libtcg to a new QEMU release

libtcg is a fork of QEMU's TCG that has been de-QEMU-ified (headers moved out of
`qemu/`, `exec/` and `accel/tcg/` into `tcg/utils/`, `tcg/exec/` and
`tcg/accel/`) and reformatted with the S2E `.clang-format` style. A plain
`git cherry-pick` or `patch` against upstream therefore never applies: every
line differs because of reformatting alone.

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

Not every libtcg file tracks upstream closely. Several utility files
(`utils/osdep.h`, `utils/cutils.c`, `utils/log.c`, `utils/bitmap.h`) are heavily
reduced S2E-specific subsets, and the `fpu/` tree still sits at QEMU v8.1.0.
These are listed in `mapping.tsv` for reference but normally want a manual look
rather than a mechanical merge.

## After merging

Re-run `run-clang-format.sh` from the S2E source root so the tree stays
normalized for the next upgrade.
