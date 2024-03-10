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
cd /mnt/disk

if [ ! -d s2e-env ]; then
    git clone https://github.com/s2e/s2e-env.git
fi

cd s2e-env

# Checkout custom s2e-env branch here
# git checkout issue/xxx-debian

python3 -m venv venv
. venv/bin/activate
pip install --upgrade pip wheel

pip install .

. venv/bin/activate

cd /mnt/disk
s2e init env
cd env/source/s2e

# Checkout custom s2e branch here
# git checkout issue/xxx-debian

cd /mnt/disk/env
s2e build
