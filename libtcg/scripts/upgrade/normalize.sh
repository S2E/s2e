#!/bin/bash
#
# Extract one file from a QEMU tag and reformat it with the S2E style, so that
# it can be compared or merged against its libtcg counterpart.
#
# Usage: QEMU_SRC=~/qemu ./normalize.sh v11.1.0 tcg/tcg.c [assumed-filename]
#
set -e

QEMU_SRC=${QEMU_SRC:-${HOME}/qemu}
CLANG_FORMAT=${CLANG_FORMAT:-clang-format-19}
STYLE_FILE=${STYLE_FILE:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/.clang-format}

TAG=$1
FILE=$2
NAME=${3:-$(basename "${FILE}")}

if [ -z "${TAG}" ] || [ -z "${FILE}" ]; then
    echo "Usage: QEMU_SRC=/path/to/qemu $0 <tag> <path-in-qemu> [assumed-filename]" >&2
    exit 1
fi

if [ ! -f "${STYLE_FILE}" ]; then
    echo "Cannot find .clang-format at ${STYLE_FILE}" >&2
    exit 1
fi

git -C "${QEMU_SRC}" show "${TAG}:${FILE}" |
    "${CLANG_FORMAT}" -style="file:${STYLE_FILE}" --assume-filename="${NAME}"
