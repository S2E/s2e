#!/bin/bash

{% include 'common-run.sh.tpl' %}

s2e run -n {{ project_name }}

TARGET="$(jq  -r '.target_files[0]' $DIR_NAME/project.json)"

CUR_DIR="$(pwd)"

echo -e "r\ninfo registers" > $S2E_LAST/dump_regs.gdb

# The PoV must set the PC and GP register to these values
BITS="$(get_bitness $TARGET)"
PLATFORM="$(get_platform $TARGET)"

if [ "$BITS" = "32" ]; then
    EXPECTED_PC="0x44556677"
    EXPECTED_GP="0xccddeeff"
    EXPECTED_SHELLCODE_REGS="eax ebx ecx edx esi edi esp ebp"
    if [ "$PLATFORM" = "linux" ]; then
        EXPECTED_GENERIC_REGS="ebp"
    elif [ "$PLATFORM" = "windows" ]; then
        EXPECTED_GENERIC_REGS="ebp"
    else
        echo Invaliid platform
        exit 1
    fi
else
    EXPECTED_PC="0x0011223344556677"
    EXPECTED_GP="0x8899aabbccddeeff"
    EXPECTED_SHELLCODE_REGS="rax rbx rcx rdx rsi rdi rsp rbp"
    EXPECTED_GENERIC_REGS="rbp"
fi

check_linux_pov() {
    local TARGET="$1"
    local RECIPE="$2"
    local EXPECTED_PC="$3"
    local EXPECTED_GP="$4"
    local EXPECTED_REG_NAME="$5"

    # Run in GDB the target binary using the generated test case PoV as input.
    # GDB will catch the segfault and dump registers.
    local CMD="gdb -batch -x $S2E_LAST/dump_regs.gdb --args $TARGET $RECIPE"
    local REG_DUMP=$($CMD)

    echo "$REG_DUMP" | grep eip | grep -q $EXPECTED_PC
    echo "$REG_DUMP" | grep $EXPECTED_REG_NAME | grep -q $EXPECTED_GP
}

check_windows_pov() {
    local TARGET="$1"
    local RECIPE="$2"
    local EXPECTED_PC="$3"
    local EXPECTED_GP="$4"
    local EXPECTED_REG_NAME="$5"

    if [ "$EXPECTED_REG_NAME" = "esp" ]; then
        # winedbg doesn't work properly if esp gets corrupted, so just ignore this this
        return
    fi

    local REG_DUMP=$(echo -e 'c\nkill\nq' | DISPLAY="" winedbg $TARGET $RECIPE)

    echo "$REG_DUMP" | grep EIP | grep -q $(echo $EXPECTED_PC | cut -d 'x' -f 2)

    local EXPECTED_REG_NAME_UP=$(echo $EXPECTED_REG_NAME | tr '[:lower:]' '[:upper:]')
    echo "$REG_DUMP" | grep $EXPECTED_REG_NAME_UP | grep -q $(echo $EXPECTED_GP | cut -d 'x' -f 2)
}

# Check that the POV actually reproduces the vulnerability
check_pov() {
    local TARGET="$1"
    local RECIPE="$2"
    local EXPECTED_PC="$3"
    local EXPECTED_GP="$4"
    local EXPECTED_REG_NAME="$5"

    if [ "x$PLATFORM" = "xlinux" ]; then
        check_linux_pov $TARGET $RECIPE $EXPECTED_PC $EXPECTED_GP $EXPECTED_REG_NAME
    elif [ "x$PLATFORM" = "xwindows" ]; then
        # XXX: winedbg doesn't work properly on 64-bit binaries, the debugger hangs
        # when there is a crash and the stack is messed up. We should replay these POVs
        # inside a Windows guest instead.
        if [ "$BITS" = "32" ]; then
            check_windows_pov $TARGET $RECIPE $EXPECTED_PC $EXPECTED_GP $EXPECTED_REG_NAME
        fi
    else
        echo "Unsupported platform"
        exit 1
    fi
}

# Validates that the expected files have been generated
check_expected_povs() {
    local RECIPES="$1"

    for REG in $EXPECTED_SHELLCODE_REGS; do
        if ! echo $RECIPES | grep -q "generic_shellcode_$REG"; then
            echo Did not find recipe "generic_shellcode_$REG"
            exit 1
        fi
    done

    for REG in $EXPECTED_GENERIC_REGS; do
        if ! echo $RECIPES | grep -q "generic_reg_$REG"; then
            echo Did not find recipe "generic_reg_$REG"
            exit 1
        fi
    done
}

RECIPES=$S2E_LAST/*input-recipe-type1_*

check_expected_povs "$RECIPES"

for RECIPE in $RECIPES; do
    echo Checking $RECIPE
    RECIPE_NAME="$(basename $RECIPE)"

    # Extract the desired register name from the test case file name
    EXPECTED_REG_NAME="$(echo $RECIPE_NAME | cut -d '_' -f 7 | cut -d '.' -f 1)"

    check_pov $TARGET $RECIPE $EXPECTED_PC $EXPECTED_GP $EXPECTED_REG_NAME
done
