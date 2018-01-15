#!/bin/bash

# Copyright (c) 2017, Cyberhaven
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
# Usage: ./run.sh UID GID path_to_binary [binary args...]
#

if [ $# -lt 3 ]; then
    echo "Usage: $0 uid gid path_to_binary [binary args...]"
    exit 1
fi

MUID="$1"
shift

MGID="$1"
shift

BINARY_PATH="$1"
shift

if [ ! -f "$BINARY_PATH" ]; then
  echo "$BINARY_PATH was not found. This path must exist inside the container."
  echo "If the binary is on your host machine, make sure that you mounted the host folder properly (-v docker option)."
  exit 1
fi

BINARY_PATH="$(readlink -f "$BINARY_PATH")"
BINARY="$(basename "$BINARY_PATH")"

# Project name doesn't have the extension
PROJECT="$(echo $BINARY | cut -f 1 -d '.')"

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

# S2E shared libraries are installed in a non-standard location,
# make sure the system can find them.
echo /opt/s2e/lib > /etc/ld.so.conf.d/s2e.conf
ldconfig

ROOT="$(pwd)/s2e-demo"

# Run the rest of the script with the uid/gid provided, otherwise
# new files will be owned by root.
exec sudo -u s2e /bin/bash - << EOF

if [ ! -d "$ROOT" ]; then
  s2e init -b /opt/s2e "$ROOT"
fi

cd "$ROOT"

if [ ! -d "projects/$PROJECT" ]; then
  echo "Creating new project in projects/$PROJECT"

  # Automatically download image if needed
  s2e new_project -n "$PROJECT" -d "$BINARY_PATH" $*
fi

echo Running $PROJECT
s2e run "$PROJECT"

EOF
