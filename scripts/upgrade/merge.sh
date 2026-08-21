#!/bin/bash
#
# Three-way merge every upstream-tracking file of one S2E component from one
# QEMU tag to another. See README.md for the rationale.
#
# Usage: QEMU_SRC=~/qemu ./merge.sh <component> <old-tag> <new-tag> [--apply]
#
# <component> is a directory under the S2E source root (libtcg, libutils, ...)
# that carries scripts/upgrade/{BASELINE,mapping.tsv}.
#
set -e

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "${HERE}/../.." && pwd)
QEMU_SRC=${QEMU_SRC:-${HOME}/qemu}

COMPONENT=$1
OLD=$2
NEW=$3
APPLY=$4

if [ -z "${COMPONENT}" ] || [ -z "${OLD}" ] || [ -z "${NEW}" ]; then
    echo "Usage: QEMU_SRC=/path/to/qemu $0 <component> <old-tag> <new-tag> [--apply]" >&2
    exit 1
fi

COMP_DIR="${ROOT}/${COMPONENT}"
MAPPING="${COMP_DIR}/scripts/upgrade/mapping.tsv"
if [ ! -f "${MAPPING}" ]; then
    echo "No mapping file at ${MAPPING}" >&2
    exit 1
fi
OUT=${OUT:-${HERE}/out/${COMPONENT}}

# The upstream directories this component's files come from, used to list files
# added between the two tags. Declared in mapping.tsv as "# upstream-dirs: a/ b/".
UPSTREAM_DIRS=$(sed -n 's/^# upstream-dirs:[[:space:]]*//p' "${MAPPING}")

rm -rf "${OUT}"
mkdir -p "${OUT}/base" "${OUT}/new" "${OUT}/merged"

# One rename table for the whole run. -l0 lifts git's rename limit, which
# otherwise silently skips inexact renames over a large range.
RENAMES="${OUT}/renames.tsv"
git -C "${QEMU_SRC}" diff --diff-filter=R -M -l0 --name-status "${OLD}" "${NEW}" > "${RENAMES}"

# mapping.tsv records upstream paths as of the newest release the component
# tracks, so a path may need resolving in either direction depending on which
# end of the upgrade we are looking at.
resolve_new_path() {
    local path=$1
    if git -C "${QEMU_SRC}" cat-file -e "${NEW}:${path}" 2>/dev/null; then
        echo "${path}"
        return 0
    fi
    awk -v old="${path}" -F'\t' '$2 == old { print $3; exit }' "${RENAMES}"
}

resolve_old_path() {
    local path=$1
    if git -C "${QEMU_SRC}" cat-file -e "${OLD}:${path}" 2>/dev/null; then
        echo "${path}"
        return 0
    fi
    awk -v new="${path}" -F'\t' '$3 == new { print $2; exit }' "${RENAMES}"
}

clean=0
conflicted=0
conflicted_files=()

printf '%-56s %9s %9s  %s\n' FILE S2E UPSTREAM STATUS

while IFS=$'\t' read -r lf qf; do
    case "${lf}" in '' | '#'*) continue ;; esac

    if [ ! -f "${COMP_DIR}/${lf}" ]; then
        printf '%-56s %9s %9s  %s\n' "${lf}" - - "MISSING-IN-TREE"
        continue
    fi

    name=$(basename "${lf}")
    mkdir -p "${OUT}/base/$(dirname "${lf}")" "${OUT}/new/$(dirname "${lf}")" \
             "${OUT}/merged/$(dirname "${lf}")"

    oqf=$(resolve_old_path "${qf}")
    if [ -z "${oqf}" ]; then
        printf '%-56s %9s %9s  %s\n' "${lf}" - - "ABSENT-AT-${OLD} (${qf})"
        continue
    fi
    QEMU_SRC="${QEMU_SRC}" "${HERE}/normalize.sh" "${OLD}" "${oqf}" "${name}" > "${OUT}/base/${lf}"

    nqf=$(resolve_new_path "${oqf}")
    if [ -z "${nqf}" ]; then
        printf '%-56s %9s %9s  %s\n' "${lf}" - - "REMOVED-IN-${NEW} (${qf})"
        continue
    fi
    QEMU_SRC="${QEMU_SRC}" "${HERE}/normalize.sh" "${NEW}" "${nqf}" "${name}" > "${OUT}/new/${lf}"

    s2e=$(diff "${OUT}/base/${lf}" "${COMP_DIR}/${lf}" | grep -c '^[<>]' || true)
    up=$(diff "${OUT}/base/${lf}" "${OUT}/new/${lf}" | grep -c '^[<>]' || true)

    status=ok
    renamed=
    if [ "${oqf}" != "${nqf}" ]; then
        renamed="renamed ${oqf} -> ${nqf}"
        status="${renamed}"
    fi

    cp "${COMP_DIR}/${lf}" "${OUT}/merged/${lf}"
    if git merge-file -L "${COMPONENT}" -L "qemu ${OLD}" -L "qemu ${NEW}" \
        "${OUT}/merged/${lf}" "${OUT}/base/${lf}" "${OUT}/new/${lf}" > /dev/null 2>&1; then
        clean=$((clean + 1))
    else
        n=$(grep -c '^<<<<<<<' "${OUT}/merged/${lf}" || true)
        status="CONFLICT (${n})"
        if [ -n "${renamed}" ]; then
            status="${status}, ${renamed}"
        fi
        conflicted=$((conflicted + 1))
        conflicted_files+=("${lf}")
    fi

    # Only rows with nothing to act on are hidden: unchanged upstream and not
    # renamed. A pure rename still needs its mapping.tsv row updated.
    if [ "${up}" = "0" ] && [ -z "${renamed}" ]; then
        continue
    fi
    printf '%-56s %9s %9s  %s\n' "${lf}" "${s2e}" "${up}" "${status}"
done < "${MAPPING}"

echo
echo "clean: ${clean}   conflicted: ${conflicted}   output: ${OUT}/merged"

# Files that appeared upstream since the old tag may need to be imported by
# hand; there is no way to guess their component-side name. Host-specific
# headers for other architectures are never candidates.
if [ -n "${UPSTREAM_DIRS}" ]; then
    # shellcheck disable=SC2086
    added=$(git -C "${QEMU_SRC}" diff --diff-filter=A --name-only "${OLD}" "${NEW}" -- ${UPSTREAM_DIRS} |
        awk '!/^host\/include\// || /^host\/include\/(generic|x86_64)\//')
    if [ -n "${added}" ]; then
        echo
        echo "Added upstream between ${OLD} and ${NEW} under ${UPSTREAM_DIRS} (review for import):"
        echo "${added}" | sed 's/^/  /'
    fi
fi

if [ "${APPLY}" = "--apply" ]; then
    echo
    echo "Applying merged files into ${COMP_DIR}"
    (cd "${OUT}/merged" && find . -type f -print0) |
        while IFS= read -r -d '' f; do
            cp "${OUT}/merged/${f#./}" "${COMP_DIR}/${f#./}"
        done
    if [ "${conflicted}" -gt 0 ]; then
        echo
        echo "WARNING: ${conflicted} file(s) were written with conflict markers, resolve before building:"
        printf '  %s\n' "${conflicted_files[@]}"
    fi
fi
