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

# This script performs a remote build of a local Visual Studio Project.
# Use this script if you develop on a Linux box. The remote server must
# have Visual Studio Community 2017 installed. If you have any other version,
# please modify this script accordingly

# Override these variables
REMOTE_HOST="${REMOTE_HOST:-192.168.187.140}"
REMOTE_USER="${REMOTE_USER:-s2e}"
REMOTE_FOLDER="${REMOTE_FOLDER:-build}"

# These variables define the build configuration. They are solution-specific
# but you can usually choose between Debug/Release and x64/Win32.
VS_CONFIG="${VS_CONFIG:-Debug}"
VS_PLATFORM="${VS_PLATFORM:-x64}"

VS_BUILD_OPTS="/property:Configuration=$VS_CONFIG /property:Platform=$VS_PLATFORM"
VS_ENV="C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Community\\Common7\\Tools\\VsDevCmd.bat"
PDBPARSER="C:\\users\\$REMOTE_USER\\pdbparser.exe"
REMOTE_BUILD_PATH="c:\\users\\$REMOTE_USER\\$REMOTE_FOLDER"

set -xe

if [ $# -ne 1 ]; then
    echo "Usage: $0 path/to/solution/dir"
    exit 1
fi

SOLUTION_DIR="$1"
if [ ! -d "$SOLUTION_DIR" ]; then
    echo "$SOLUTION_DIR does not exist"
    exit 1
fi

# Generate build script in the solution dir.
# This script builds the solution then extracts line information
# from PDB files suitable for use by s2e-env.
cat <<EOF >"$SOLUTION_DIR/build.bat"
call "$VS_ENV"
cd $REMOTE_BUILD_PATH
msbuild $VS_BUILD_OPTS

setlocal enabledelayedexpansion

FOR /R . %%A IN (*.sys *.exe *.dll) DO (
    echo Generating line information for %%A...
    set BIN=%%A
    set PDB=!BIN:.exe=.pdb!
    set PDB=!BIN:.sys=.pdb!
    $PDBPARSER -l %%A !PDB! > %%A.lines
)
EOF

# rsync solution directory to remote location
# skip symlinks as windows doesn't understand them
rsync -rvz --no-links --delete "$SOLUTION_DIR"/* "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_FOLDER}"

# run msbuild remotely
ssh "${REMOTE_USER}@${REMOTE_HOST}" "cmd /c $REMOTE_BUILD_PATH\\build.bat"

# rsync back the build artifacts
rsync -rvz "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_FOLDER}"/* "$SOLUTION_DIR"
