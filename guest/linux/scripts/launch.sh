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

# This script is run in a Linux guest. If you built your image with s2e-env it
# will automatically run at user login.


# NOTE: be careful to not disclose magic serial port messages in case
# the output of this script is redirected to serial port.
set -v

# When QEMU reads this message on the serial port, it exits immediately.
# The space at the end of the string is important.
# XXX: fix hardcoded snapshot name
SECRET_MESSAGE_KILL='?!?MAGIC?!?k 0 '
SECRET_MESSAGE_SAVEVM='?!?MAGIC?!?s ready '

# If the image is run in non-S2E mode execution will loop indefinitely on
# s2eget. This gives the user the opportunity to take a snapshot. When the
# image is rebooted into S2E mode it will retrieve the bootstrap script and
# start executing it immediately.
echo "booted kernel $(uname -r)" > /dev/ttyS0

echo "$SECRET_MESSAGE_SAVEVM" > /dev/ttyS0

./s2ecmd get bootstrap.sh
chmod +x bootstrap.sh
./bootstrap.sh 2>&1 > /dev/ttyS0
./s2ecmd kill 0 "bootstrap terminated"
