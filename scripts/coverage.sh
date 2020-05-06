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

if [ -z "${LLVM_BIN}" ]; then
    echo "Usage: LLVM_BIN=/path/to/llvm/bin ${0}"
    echo ""
    echo "    LLVM_BIN - Path to the LLVM's binaries"
    exit 1
fi

# Compile your binary with -fprofile-instr-generate -fcoverage-mapping

LLVM_PROFILE_FILE="profile.profraw" $*
$LLVM_BIN/llvm-profdata merge -sparse profile.profraw -o profile.profdata
$LLVM_BIN/llvm-cov export --format=lcov $1 -instr-profile=profile.profdata > $1.coverage.lcov
genhtml -o $1.coverage $1.coverage.lcov

