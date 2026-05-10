#!/bin/sh
# Copyright (C) 2021 Vitaly Chipounov
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

set -xe

ROOTDIR=/mnt/disk

REPO_BRANCH=master
# SCRIPTS_BRANCH=qemu-10.2
# S2EENV_BRANCH=qemu-10.2
# LIBS2E_BRANCH=issue/qemu-10.2-tmp
# QEMU_BRANCH=stable-10.2-se

cd "$ROOTDIR"

if [ ! -d s2e-env ]; then
    git clone https://github.com/s2e/s2e-env.git
fi

cd "$ROOTDIR/s2e-env"

if [ "x$S2EENV_BRANCH" != "x" ]; then
    git checkout "$S2EENV_BRANCH"
fi

python3 -m venv venv
. venv/bin/activate
pip install --upgrade pip wheel
pip install .
. venv/bin/activate

cd "$ROOTDIR"
s2e init -mb "$REPO_BRANCH" env

if [ "x$LIBS2E_BRANCH" != "x" ]; then
    cd "$ROOTDIR/env/source/s2e"
    git checkout "$LIBS2E_BRANCH"
fi

if [ "x$SCRIPTS_BRANCH" != "x" ]; then
    cd "$ROOTDIR/env/source/scripts"
    git checkout "$SCRIPTS_BRANCH"
fi

if [ "x$QEMU_BRANCH" != "x" ]; then
    cd "$ROOTDIR/env/source/qemu"
    git checkout "$QEMU_BRANCH"
fi

cd "$ROOTDIR/env"
s2e build
