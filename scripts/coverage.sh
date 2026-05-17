#!/bin/bash

# Copyright (c) 2020 Vitaly Chipounov
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

set -e

if [ $# -eq 0 ]; then
    echo "Usage: [LLVM_BIN=/path/to/llvm/bin] [LLVM_PROFDATA=llvm-profdata-19] [LLVM_COV=llvm-cov-19] ${0} <binary> [args...]"
    echo ""
    echo "  Defaults to llvm-profdata-19 and llvm-cov-19."
    echo "  Set LLVM_BIN to override both tools' directory (uses unversioned names)."
    echo "  Set LLVM_PROFDATA or LLVM_COV individually to override specific tools."
    echo ""
    echo "  The binary must be compiled with: -fprofile-instr-generate -fcoverage-mapping"
    exit 1
fi

LLVM_PROFDATA="${LLVM_PROFDATA:-llvm-profdata-19}"
LLVM_COV="${LLVM_COV:-llvm-cov-19}"

if [ -n "${LLVM_BIN}" ]; then
    LLVM_PROFDATA="${LLVM_BIN}/llvm-profdata"
    LLVM_COV="${LLVM_BIN}/llvm-cov"
fi

LLVM_PROFILE_FILE="profile.profraw" $*
"${LLVM_PROFDATA}" merge -sparse profile.profraw -o profile.profdata
"${LLVM_COV}" export --format=lcov $1 -instr-profile=profile.profdata > $1.coverage.lcov
genhtml --ignore-errors unsupported,inconsistent,category -o $1.coverage $1.coverage.lcov

