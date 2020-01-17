#!/bin/bash

# Copyright (c) 2017 Dependable Systems Laboratory, EPFL
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

#
# Automatically run clang-format on the S2E source code
#
# You must specify the path to the clang-format binary in the CLANG_FORMAT
# variable. This script must be run from the root directory of the S2E code
# repository
#

set -e

if [ -z "${CLANG_FORMAT}" ]; then
    echo "Usage: CLANG_FORMAT=/path/to/clang-format ${0}"
    echo ""
    echo "    CLANG_FORMAT - Path to the clang-format binary"
    exit 1
fi

FILE_EXTS=".c .h .cpp .hpp .cc .hh .cxx"

for EXT in ${FILE_EXTS}; do
    echo "Applying clang-format to ${EXT} files..."
    find -type f -name "*${EXT}"                    \
        -not -path "./guest/windows/*"              \
        -not -path "./lua/*"                        \
        -not -path "./scripts/*"                    \
        -not -path "./testsuite/faultinj-scannersys/*"  \
        -exec ${CLANG_FORMAT} -i -style=file {} +
done
