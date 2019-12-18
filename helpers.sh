get_bitness() {
    local TARGET_NAME="$(basename $1)"
    if echo $TARGET_NAME | grep -q 32; then
        echo 32
    elif echo $TARGET_NAME | grep -q 64; then
        echo 64
    else
        echo "Invalid bitness encoded in $TARGET_NAME"
        exit 1
    fi
}

get_platform() {
    local TARGET_NAME="$(basename $1)"
    if echo $TARGET_NAME | grep -q windows; then
        echo windows
    elif echo $TARGET_NAME | grep -q linux; then
        echo linux
    else
        echo "Invalid platform encoded in $TARGET_NAME"
        exit 1
    fi
}

# This function takes the path to an executable file (ELF, PE), a function name in that
# executable, and returns the corresponding address.
get_func_addr() {
    local BINARY="$1"
    local FUNCTION_NAME="$2"
    local ADDR=""
    if echo $BINARY | grep -q ".exe"; then
        ADDR="$(objdump -S $BINARY  | grep "<_$FUNCTION_NAME>:" | head -n 1 | cut -d ' ' -f 1)"
        if [ "x$ADDR" = "x" ]; then
            ADDR="$(objdump -S $BINARY  | grep "<$FUNCTION_NAME>:" | head -n 1 | cut -d ' ' -f 1)"
        fi
    else
        ADDR="$(objdump -t $BINARY  | grep $FUNCTION_NAME | cut -d ' ' -f 1 | head -n 1)"
    fi

    if [ "x$ADDR" = "x" ]; then
        return
    fi
    echo 0x$ADDR
}
