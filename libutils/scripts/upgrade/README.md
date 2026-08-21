# Upgrading libutils' vendored QEMU utilities to a new QEMU release

`include/utils/` and `src/utils/` hold a subset of QEMU's `util/`,
`include/qemu/` and `host/include/` that was de-QEMU-ified (headers moved out
of `qemu/` into `utils/`) and reformatted with the S2E `.clang-format` style.
They used to live in libtcg under `tcg/utils/`; they moved here because they
depend on no target macro and libtcg is configured once per target, so keeping
them in libtcg compiled every object six times per build type.

A plain `git cherry-pick` or `patch` against upstream never applies: every line
differs because of reformatting alone. The trick that makes upgrades tractable
is to *normalize the formatting first*. Running an upstream file through
`clang-format` with the S2E style reduces the difference against its libutils
counterpart to the genuine S2E delta.

The upgrade is then an ordinary three-way merge:

    base    = clang-formatted upstream file at the OLD tag
    theirs  = clang-formatted upstream file at the NEW tag
    ours    = the current libutils file

    git merge-file ours base theirs

The rest of libutils (QAPI, QObject, the visitors, coroutines, fsigc++) is not
covered here; it diverged from QEMU long ago and is maintained by hand.

## Files

- `mapping.tsv` — libutils path -> upstream QEMU path, one pair per line, tab
  separated. Only files that track upstream are listed; S2E-original files
  (`utils/cache.h`, `utils/mutex.h`, `utils/spinlock.h`, `utils/rounding.h`)
  are deliberately absent.
- `BASELINE` — the QEMU tag `mapping.tsv` paths and the current tree correspond
  to. Update it (and any renamed paths in `mapping.tsv`) once an upgrade lands.
- `normalize.sh` — extract one file from a QEMU tag and clang-format it.
- `merge.sh` — normalize every mapped file at both tags and three-way merge.

libtcg has its own copy of the same tooling under `libtcg/scripts/upgrade/`,
covering the TCG core, the x86_64 backend, the fpu and the three utility files
that stay behind (`utils/bswap.h`, `utils/cpu-float.h`, `utils/log.*`). Both
should be re-run when a QEMU tag is bumped.

## Running an upgrade

    export QEMU_SRC=~/qemu
    ./merge.sh v10.2.0 v11.1.0            # writes into ./out, reports conflicts
    ./merge.sh v10.2.0 v11.1.0 --apply    # same, but writes back into the tree

`merge.sh` follows upstream renames automatically (via `git diff -M`) and
reports files that were deleted upstream or added since the old tag, both of
which need a human decision.

Not every file tracks upstream closely. The ones below the "hand written"
marker in `mapping.tsv` (`utils/osdep.h`, `utils/cutils.*`, `utils/bitmap.h`)
are heavily reduced S2E-specific subsets rather than vendored copies, and are
still v8.1.0-era. They are listed for reference but want a manual look rather
than a mechanical merge.

Two S2E deviations in the merged code are deliberate and must survive future
merges:

- `host/generic/atomic128-cas.h` renames the `new` parameter to `_new`, since
  these headers are included from C++.
- `utils/osdep.h` carries what upstream keeps in `include/qemu/compiler.h`.

`utils/qtree.h`, `utils/int128.h` and `utils/host-utils.h` read
`HAVE_GLIB_WITH_SLICE_ALLOCATOR`, `CONFIG_INT128` and `HOST_BIG_ENDIAN`.
`libutils/src/CMakeLists.txt` defines them, and every component that includes
these headers has to define them the same way, or the struct layouts disagree
across translation units.

## After merging

Re-run `run-clang-format.sh` from the S2E source root so the tree stays
normalized for the next upgrade.
