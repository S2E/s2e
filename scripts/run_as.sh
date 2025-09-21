#!/bin/bash

# Copyright (c) 2018, Cyberhaven
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

# This script allows running a command in the docker image with the given UID/GID.
#
# Usage: ./run_as.sh UID GID command args...
#

if [ $# -lt 3 ]; then
    echo "Usage: $0 uid gid path_to_binary [binary args...]"
    exit 1
fi

MUID="$1"
shift

MGID="$1"
shift

# Verify that the specified group and user ids don't exist locally.
# If so, delete them. This may happen if the host OS is not Debian-based,
# where user ids may conflict with those preinstalled in the docker image.
GROUP=$(getent group $MGID | cut -d ':' -f 1)
USER=$(getent passwd $MUID | cut -d ':' -f 1)

if [ "x$USER" != "x" ]; then
  userdel $USER
fi

if [ "x$GROUP" != "x" ]; then
  groupdel $GROUP
fi

groupadd -g $MGID s2e
useradd -u $MUID -g s2e s2e

# Run the rest of the script with the uid/gid provided, otherwise
# new files will be owned by root.
exec sudo -E -u s2e $*
