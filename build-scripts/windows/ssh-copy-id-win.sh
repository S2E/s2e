#!/bin/bash
# Copyright (c) 2018 Cyberhaven
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

# This script adds the authorized key of the current user to the remote Windows
# machine. The machine should have an SSH server running.

if [ $# -ne 1 ]; then
    echo "Usage: $0 user@host"
    exit 1
fi

PUBKEY=~/.ssh/id_rsa.pub

if [ ! -f "$PUBKEY" ]; then
    echo "$PUBKEY does not exist"
    exit 1
fi

HOST="$1"

if ! echo $HOST | grep -q '@'; then
    echo "Use user@host format instead of $HOST"
    exit
fi

USER="$(echo $HOST | cut -d '@' -f 1)"

PKVAR="$(cat $PUBKEY)"

REMOTE_FILE="c:\\users\\$USER\\.ssh\\authorized_keys"
echo "Adding contents of $PUBKEY to $REMOTE_FILE..."

ssh "$HOST" "echo $PKVAR >> $REMOTE_FILE"
