#!/bin/bash
# Copyright (c) 2019 Cyberhaven
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

# This script is the Revgen driver. It invokes IDA/Revgen with the right arguments,
# depending on the type of specified binary.
#
# The script produces the following files (assuming a binary called CADET_00001):
#
#   CADET_00001.bc          => The translated LLVM bitcode file
#   CADET_00001.ida.log     => The output log of IDA, useful for debugging
#   CADET_00001.ll          => llvm-dis output of the bitcode file
#   CADET_00001.lst         => IDA disassembly listing
#   CADET_00001.pbcfg       => The CFG in protobuf format, produced my the McSema script
#   CADET_00001.rev         => Only for CGC binaries: equivalent native Linux binary
#   CADET_00001.stdout.txt  => The output log of the McSema script
#   CADET_00001.stats       => Various stats about the translation
#
# Use REVGEN_PREFIX="gdb --args" to run Revgen in gdb.
# By default, this script runs IDA and clang with a timeout of 120 seconds.
# Set the TIMEOUT variable to override this (e.g., export TIMEOUT=240).
#
# Translated CGC binaries are compiled with -O3 and link time optimization
# in order to remove the bulk of the CPU emulation library. This requires
# the gold linker and plugin.
#
# IDA_ROOT must point to the root of your IDA installation directory (e.g., /opt/ida-6.8).
# S2E_PREFIX must point to the S2E installation prefix (e.g., /opt).
# If not set, this script will try to auto-detect the value of S2E_PREFIX based on its location.

# Unset these for debugging
# set -e # Abort at the first error
# set -x


#############################################################################
TIMEOUT=${TIMEOUT:-120}
IDA_ROOT=${IDA_ROOT:-/opt/ida-6.8}

# This function guesses the prefix where Revgen is installed,
# based on the location of this script. E.g., it could be /usr/local
# if this script is in /usr/local/bin/.
guess_prefix() {
    local SCRIPT_DIR="$(dirname "$0")"
    local PREFIX="$(cd "$SCRIPT_DIR/.." && pwd)"
    if [ ! -x "$PREFIX/bin/revgen32" ]; then
        echo "/opt"
        return
    fi

    echo $PREFIX
}

S2E_PREFIX=${S2E_PREFIX:-$(guess_prefix)}

if [ $# -ne 1 ]; then
    echo "Usage: $0 /path/to/binary"
    exit 1
fi

INPUT_BINARY="$1"
if [ ! -f "$INPUT_BINARY" ]; then
    echo "$INPUT_BINARY does not exist."
    exit 1
fi

#############################################################################

# Returns the binary type, CGC or Unknown for now.
get_binary_type() {
    local INPUT_BINARY="$1"
    local SIGNATURE="$(hexdump -n 4 -v -e '/1 "%02X "' $INPUT_BINARY)"
    if [ "$SIGNATURE" = "7F 43 47 43 " ]; then
        echo "CGC"
    else
        echo "Unknown"
    fi
}

# Returns 32 or 64 depending on the binary type, or Unknown if could not
# determine the bitness.
get_binary_bits() {
    local INPUT_BINARY="$1"
    local FILE="$(file -L $INPUT_BINARY)"
    local TYPE=$(get_binary_type "$INPUT_BINARY")
    if echo $FILE | grep -q "x86-64"; then
        echo 64
    elif echo $FILE | grep -q "80386"; then
        echo 32
    elif [ "$TYPE" = "CGC" ]; then
        echo 32
    else
        echo "Unknown: $FILE"
    fi
}

# Returns 1 if the first file is more recent than the 2nd
is_more_recent() {
    local D1=$(stat -L -c "%Y" "$1")
    local D2=$(stat -L -c "%Y" "$2")

    if [ "x$D1" = "x" ]; then
        D1=0
    fi

    if [ "x$D2" = "x" ]; then
        D2=0
    fi

    if [ $D1 -gt $D2 ]; then
        echo 1
    else
        echo 0
    fi
}

# Returns the current time in milliseconds
get_time_ms() {
    echo $(($(date +%s%N)/1000000))
}

IDA="$IDA_ROOT/idal64"
IDAFLAGS="$IDAFLAGS -A -B"

REVGEN32="$S2E_PREFIX/bin/revgen32"
REVGEN64="$S2E_PREFIX/bin/revgen64"
GETCFG="$S2E_PREFIX/bin/mcsema_get_cfg.py"

BITCODELIB32="${S2E_PREFIX}/lib/X86BitcodeLibrary.bc"
BITCODELIB64="${S2E_PREFIX}/lib/X8664BitcodeLibrary.bc"
RUNTIMELIB32="${S2E_PREFIX}/lib/X86RuntimeLibrary.bc"

LLVMDIS="${S2E_PREFIX}/bin/llvm-dis"
CLANG="${S2E_PREFIX}/bin/clang"

if [ ! -x "$IDA" ]; then
    echo "$IDA does not exist. Please set IDA_ROOT to the location of your IDA installation."
    exit 1
fi

for f in $REVGEN32 $REVGEN64 $GETCFG $LLVMDIS $CLANG $BITCODELIB32 $BITCODELIB64; do
    if [ ! -f "$f" ]; then
        echo "$f does not exist. Please set S2E_PREFIX to the prefix of your Revgen installation."
        exit 1
    fi
done

# Paths to various output files that Revgen generates
PBCFG="${INPUT_BINARY}.pbcfg"
IDA_LOG="${INPUT_BINARY}.ida.log"
OUTPUT_BC="${OUTPUT_BC:-${INPUT_BINARY}.bc}"
OUTPUT_LL="${OUTPUT_LL:-${INPUT_BINARY}.ll}"
OUTPUT_BINARY="${OUTPUT_BINARY:-${INPUT_BINARY}.rev}"
OUTPUT_STATS="${OUTPUT_STATS:-${INPUT_BINARY}.stats}"

TIMEOUT_CMD="timeout -k $(($TIMEOUT + 10)) $TIMEOUT"

# Invokes IDA in headless mode to generate the CFG in protobuf format
generate_cfg() {
    echo "[IDA    ] Writing CFG to $PBCFG..."

    # Need a timeout because some very large binaries can take very long to disassemble
    TVHEADLESS=1 $TIMEOUT_CMD "$IDA" -L"$IDA_LOG" $IDAFLAGS -S"\"$GETCFG\" --batch -l --output \"$PBCFG\" $MCSEMA_FLAGS" "$INPUT_BINARY" > /dev/null

    if [ $? -ne 0 ]; then
        echo "IDA failed. Please check $IDA_LOG for details."
        return 1
    fi

    if [ ! -s "$PBCFG" ]; then
        echo "IDA returned success but no CFG has been generated. Please check $IDA_LOG for details."
        return 1
    fi
}

# Invokes the right flavor of Revgen based on the bitness of the input binary
translate() {
    local BITS="$(get_binary_bits $INPUT_BINARY)"
    if [ "x$BITS" = "x32" ]; then
        REVGEN="$REVGEN32"
        BITCODELIB="$BITCODELIB32"
    elif  [ "x$BITS" = "x64" ]; then
        REVGEN="$REVGEN64"
        BITCODELIB="$BITCODELIB64"
    else
        echo "Could not determine architecture for $INPUT_BINARY ($BITS)."
        return 1
    fi

    echo "[REVGEN ] Translating $INPUT_BINARY to $OUTPUT_BC..."
    $REVGEN_PREFIX "$REVGEN" -binary="$INPUT_BINARY" -mcsema-cfg="$PBCFG" -output="$OUTPUT_BC" -bitcodelib="$BITCODELIB" $REVGEN_FLAGS
    if [ $? -ne 0 ]; then
        echo "Revgen failed."
        return 1
    fi
}

# Disassembles the bitcode file generated by Revgen
disassemble() {
    echo "[LLVMDIS] Generating LLVM disassembly to $OUTPUT_LL..."
    "$LLVMDIS" -o "$OUTPUT_LL" "$OUTPUT_BC"
    if [ $? -ne 0 ]; then
        rm -f "$OUTPUT_LL"
        echo "llvm-dis failed"
        return 1
    fi
}

# Compiles and links the bitcode file.
# NOTE: only works for CGC binaries
compile() {
    # We only support compilation for CGC binaries for now
    SIGNATURE=$(get_binary_type "$INPUT_BINARY")

    if [ "$SIGNATURE" = "CGC" ]; then
        echo "[CLANG  ] Compiling LLVM bitcode of CGC binary to native binary $OUTPUT_BINARY..."

        # Use the gold linker to have link time optimization. LTO will remove all the unused
        # functions from the run time library, resulting in much smaller binaries.
        # Very large files may get stuck in the linker for hours, so we need a timeout.
        $TIMEOUT_CMD "$CLANG" -g -m32 -O3 -o "$OUTPUT_BINARY" "$OUTPUT_BC" "$RUNTIMELIB32" -lm -lstdc++ -flto -fuse-ld=gold
        if [ $? -ne 0 ]; then
            rm -f "$OUTPUT_BINARY"
            echo "clang failed"
            return 1
        fi
    fi
}


HAS_ERRORS=0

build() {
    TIME1="$(get_time_ms)"
    local DO_GEN_CFG=$(is_more_recent "$INPUT_BINARY" "$PBCFG")

    if [ $DO_GEN_CFG -eq 1 -o ! -s $PBCFG  ]; then
        generate_cfg
        if [ $? -ne 0 ]; then
            return 1
        fi
    else
        echo "[IDA    ] Skipping CFG generation, $PBCFG is more recent than the binary."
    fi

    TIME2="$(get_time_ms)"
    translate
    if [ $? -ne 0 ]; then
        return 1
    fi

    TIME3="$(get_time_ms)"
    disassemble
    if [ $? -ne 0 ]; then
        return 1
    fi

    TIME4="$(get_time_ms)"
    compile
    if [ $? -ne 0 ]; then
        return 1
    fi
    TIME5="$(get_time_ms)"
}

# Record various stats about the translation
gen_stats() {
    # Init default values for stats, we want to show
    # as much as possible in the stats file, even if some steps fail.
    local INPUT_BINARY_SIZE=$(stat -c%s "$INPUT_BINARY")
    local OUTPUT_BINARY_SIZE="N/A"
    local OUTPUT_BC_SIZE="N/A"
    local PBCFG_SIZE="N/A"
    local IDATIME_MS="N/A"
    local REVENG_TIME_MS="N/A"
    local COMPILE_TIME_MS="N/A"

    if [ -f "$OUTPUT_BINARY" ]; then
        OUTPUT_BINARY_SIZE=$(stat -c%s "$OUTPUT_BINARY")
        COMPILE_TIME_MS=$(($TIME5 - $TIME4))
    fi

    if [ -f "$OUTPUT_BC" ]; then
        OUTPUT_BC_SIZE=$(stat -c%s "$OUTPUT_BC")
        REVENG_TIME_MS=$(($TIME3 - $TIME2))
    fi

    if [ -s "$PBCFG" ]; then
        PBCFG_SIZE=$(stat -c%s "$PBCFG")
        IDATIME_MS=$(($TIME2 - $TIME1))
    fi

    echo -e "BinaryName\tInputBinSize\tRevgenBinSize\tRevgenBcSize\tCfgSize\tIdaTimeMs\tRevgenTimeMs\tCompileTimeMs" > "$OUTPUT_STATS"
    echo -e "$(basename $INPUT_BINARY)\t$INPUT_BINARY_SIZE\t$OUTPUT_BINARY_SIZE\t$OUTPUT_BC_SIZE\t$PBCFG_SIZE\t$IDATIME_MS\t$REVENG_TIME_MS\t$COMPILE_TIME_MS" >> "$OUTPUT_STATS"
}

build
if [ $? -ne 0 ]; then
    HAS_ERRORS=1
fi

gen_stats

exit $HAS_ERRORS
