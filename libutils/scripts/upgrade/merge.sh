#!/bin/bash
#
# Three-way merge every vendored QEMU utility in libutils from one QEMU tag to
# another. See README.md for the rationale.
#
# Usage: QEMU_SRC=~/qemu ./merge.sh <old-tag> <new-tag> [--apply]
#
set -e

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LIBUTILS=$(cd "${HERE}/../.." && pwd)
QEMU_SRC=${QEMU_SRC:-${HOME}/qemu}
OUT=${OUT:-${HERE}/out}

OLD=$1
NEW=$2
APPLY=$3

if [ -z "${OLD}" ] || [ -z "${NEW}" ]; then
    echo "Usage: QEMU_SRC=/path/to/qemu $0 <old-tag> <new-tag> [--apply]" >&2
    exit 1
fi

rm -rf "${OUT}"
mkdir -p "${OUT}/base" "${OUT}/new" "${OUT}/merged"

clean=0
conflicted=0

# mapping.tsv records upstream paths as of the newest release libutils tracks, so
# a path may need resolving in either direction depending on which end of the
# upgrade we are looking at.
resolve_new_path() {
    local path=$1
    if git -C "${QEMU_SRC}" cat-file -e "${NEW}:${path}" 2>/dev/null; then
        echo "${path}"
        return 0
    fi
    git -C "${QEMU_SRC}" diff --diff-filter=R -M --name-status "${OLD}" "${NEW}" |
        awk -v old="${path}" -F'\t' '$2 == old { print $3; exit }'
}

resolve_old_path() {
    local path=$1
    if git -C "${QEMU_SRC}" cat-file -e "${OLD}:${path}" 2>/dev/null; then
        echo "${path}"
        return 0
    fi
    git -C "${QEMU_SRC}" diff --diff-filter=R -M --name-status "${OLD}" "${NEW}" |
        awk -v new="${path}" -F'\t' '$3 == new { print $2; exit }'
}

printf '%-56s %9s %9s  %s\n' FILE S2E UPSTREAM STATUS

while IFS=$'\t' read -r lf qf; do
    case "${lf}" in '' | '#'*) continue ;; esac

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

    s2e=$(diff "${OUT}/base/${lf}" "${LIBUTILS}/${lf}" | grep -c '^[<>]' || true)
    up=$(diff "${OUT}/base/${lf}" "${OUT}/new/${lf}" | grep -c '^[<>]' || true)

    status=ok
    [ "${oqf}" != "${nqf}" ] && status="renamed ${oqf} -> ${nqf}"

    cp "${LIBUTILS}/${lf}" "${OUT}/merged/${lf}"
    if git merge-file -L libutils -L "qemu ${OLD}" -L "qemu ${NEW}" \
        "${OUT}/merged/${lf}" "${OUT}/base/${lf}" "${OUT}/new/${lf}" > /dev/null 2>&1; then
        clean=$((clean + 1))
    else
        n=$(grep -c '^<<<<<<<' "${OUT}/merged/${lf}" || true)
        status="CONFLICT (${n})"
        conflicted=$((conflicted + 1))
    fi

    [ "${up}" = "0" ] && continue
    printf '%-56s %9s %9s  %s\n' "${lf}" "${s2e}" "${up}" "${status}"
done < "${HERE}/mapping.tsv"

echo
echo "clean: ${clean}   conflicted: ${conflicted}   output: ${OUT}/merged"

# Files that appeared upstream since the old tag may need to be imported by
# hand; there is no way to guess their libutils name.
echo
echo "Added upstream between ${OLD} and ${NEW} (review for import):"
git -C "${QEMU_SRC}" diff --diff-filter=A --name-only "${OLD}" "${NEW}" -- \
    util/ include/qemu/ host/include/ | sed 's/^/  /'

if [ "${APPLY}" = "--apply" ]; then
    echo
    echo "Applying merged files into ${LIBUTILS}"
    (cd "${OUT}/merged" && find . -type f -print0) |
        while IFS= read -r -d '' f; do
            cp "${OUT}/merged/${f#./}" "${LIBUTILS}/${f#./}"
        done
fi
