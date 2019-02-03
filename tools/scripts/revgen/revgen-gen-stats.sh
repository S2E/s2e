#!/bin/bash
# Copyright (c) 2018-2019, Cyberhaven
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Note: IDA_ROOT and S2E_PREFIX should be set, otherwise revgen invocation will fail

if [ $# -ne 2 ]; then
    echo "Usage: $0 /path/to/binaries /path/to/stats"
    exit 1
fi

REVGEN_OUT_DIR="$1"
if [ ! -d "$REVGEN_OUT_DIR" ]; then
    echo "$REVGEN_OUT_DIR does not exist"
    exit 1
fi

STATS_FILE="$2"

guess_revgen_path() {
    local SCRIPT_DIR="$(dirname "$0")"
    local PREFIX="$(cd "$SCRIPT_DIR" && pwd)"
    if [ -x "$PREFIX/revgen.sh" ]; then
        echo $PREFIX/revgen.sh
    fi
}

REVGEN="$(guess_revgen_path)"
if [ ! -x "$REVGEN" ]; then
    echo "Could not find Revgen ($REVGEN), make sure that this script is in the same directory as revgen.sh"
    exit 1
fi

get_binaries() {
    local DIR="$1"

    cd "$DIR" &&
    for file in *; do
        if [ -x "$file" ]; then
            printf '%s\n' "${file%.*}"
        fi
    done | sort | uniq
}

translate_binaries() {
    local DIR="$1"
    local BINARIES="$2"
    (cd $DIR && echo $BINARIES | sed 's/ /\n/g' | parallel $REVGEN)
}

generate_stats() {
    local DIR="$1"
    local BINARIES="$2"
    local PRINTED_HEADER=0

    for b in $BINARIES; do
        # TODO: this won't work if the first binary has no stats file
        if [ $PRINTED_HEADER -eq 0 ]; then
            head -n 1 "$DIR/$b.stats"
            PRINTED_HEADER=1
        fi

        if [ -f "$DIR/$b.stats" ]; then
            tail -n 1 "$DIR/$b.stats"
        else
            echo "$b"
        fi
    done
}

BINARIES="$(get_binaries "$REVGEN_OUT_DIR")"
translate_binaries "$REVGEN_OUT_DIR" "$BINARIES"
generate_stats "$REVGEN_OUT_DIR" "$BINARIES" > "$STATS_FILE"
