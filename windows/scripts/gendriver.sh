#!/bin/sh
# Copyright (C) 2017, Cyberhaven
# All rights reserved.
#
# Licensed under the Cyberhaven Research License Agreement.

# This script automatically extracts kernels from Windows ISO images
# and generates the winmonitor_gen.c file that is used by the S2E kernel
# driver in order to parse internal Windows data structures.
#
# Run this script if you want to add support for a new Windows version.
# After the script is done, rebuild the driver.

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 /path/to/windows/iso/folder"
    exit 1
fi

ISO_DIR="$1"
CUR_DIR="$(pwd)"
SCRIPT_DIR="$(cd "$(dirname $0)" && pwd)"
BASE_DIR="$SCRIPT_DIR/../"
OUTPUT_DIR="$BASE_DIR/kernels"

DRIVER_OUTPUT="$BASE_DIR/driver/src/winmonitor_gen.c"
PDBPARSER="$CUR_DIR/x64/Release/pdbparser.exe"

if [ ! -f "$PDBPARSER" ]; then
    echo "$PDBPARSER does not exist."
    echo "Please build the s2e.sln solution with Visual Studio in release mode."
    exit 1
fi

if [ ! -d $ISO_DIR ]; then
    echo "$ISO_DIR does not exist"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

./scripts/extract_kernels.py  --iso-dir "$ISO_DIR" -o "$OUTPUT_DIR"

cd "$OUTPUT_DIR"
for f in *.exe; do
    $SCRIPT_DIR/symchk.py "$f"
done

cd "$CUR_DIR"
./scripts/gendriver.py -d "$OUTPUT_DIR" -p "$PDBPARSER" -o "$DRIVER_OUTPUT"

echo "The S2E driver file $DRIVER_OUTPUT has been updated. Please rebuild the solution."
