#!/bin/sh

set -e

echo "Patching s2e-config.lua..."

. ${TESTSUITE_ROOT}/helpers.sh

PROJECT_NAME="$(basename $PROJECT_DIR)"

SCANF_CS_ADDR=$(objdump -S $TARGET | grep scanf | grep call | cut -d ':' -f 1 | xargs)
if [ "x$SCANF_CS_ADDR" = "x" ]; then
    echo "Could not get call site of scanf instruction"
    exit 1
fi

PLATFORM=$(get_platform "$TARGET")

cat << EOF >> $PROJECT_DIR/s2e-config.lua

add_plugin("FunctionMonitor")
add_plugin("LuaFunctionInstrumentation")
add_plugin("LuaInstructionInstrumentation")

pluginsConfig.LuaFunctionInstrumentation = {
    instrumentation = {
    }
}

pluginsConfig.LuaInstructionInstrumentation = {
    instrumentation = {
        scanf_skip = {
            module_name = "$(basename $TARGET)",
            name = "scanf_skip",
            pc = 0x$SCANF_CS_ADDR,
        },
    }
}

printf = function(s, ...)
    return io.write(s:format(...))
end

g_platform = "$PLATFORM"

-- This instrumentation intercepts the scanf callsite in order to inject
-- symbolic data without actually calling scanf. This reduces path explosion.
function scanf_skip(state, instrumentation_state)
    g_s2e:debug("called scanf instrumentation")

    ptr_size = state:getPointerSize()

    if ptr_size == 4 then
        -- 32-bit calling convention
        sp = state:regs():getSp()
        printf("sp: %#x ptr_size: %d\n", sp, ptr_size)

        -- Compute the stack address that contains the address
        -- to the concrete buffer (second argument of scanf)
        buffer_addr_ptr = sp + ptr_size * 1
        printf("buffer_addr_ptr: %#x\n", buffer_addr_ptr)

        -- Read the pointer to the buffer from the stack
        buffer_addr = state:mem():readPointer(buffer_addr_ptr)
        if buffer_addr == nil then
           g_s2e:debug("Could not read pointer")
           g_s2e:exit(-1)
        end
        printf("buffer_addr: %#x\n", buffer_addr)
    else
        if g_platform == "windows" then
            -- Microsoft x64 calling convention
            -- 2nd parameter is in RDX=2
            buffer_addr = state:regs():read(2 * ptr_size, ptr_size)
        else
            -- System V AMD64 ABI
            -- 2nd parameter is in RSI=6
            buffer_addr = state:regs():read(6 * ptr_size, ptr_size)
        end
    end

    -- Make 30 bytes of that buffer symbolic
    state:mem():makeSymbolic(buffer_addr, 30, "buffer")

    -- Write 1 to eax. This is what scanf would have returned
    -- if it actually got executed.
    state:regs():write(0, 1, ptr_size)

    -- Don't execute the instruction, jump straight to the next one.
    instrumentation_state:skipInstruction(1)
end

EOF

FUNCTIONS="is_good"
for f in $FUNCTIONS; do
    ADDR=$(get_func_addr $TARGET $f)
    if [ "x$ADDR" = "x" ]; then
        echo "Could not get address for $f"
        exit 1
    fi

cat << EOF >> $PROJECT_DIR/s2e-config.lua
    pluginsConfig.LuaFunctionInstrumentation.instrumentation["$f"] = {
        module_name = "$(basename $TARGET)",
        name = "$f",
        pc = $ADDR,
        param_count = 0,
        fork = false,
        convention = "cdecl",
    }

    -- This instrumentation kills a path as soon as it detects
    -- that the path will not lead to the answer. This prevents the
    -- wrong paths from forking further, eliminating path explosion.
    function $f(state, instrumentation_state, is_call)
        if is_call then
            return
        end

        -- 1 means that we get a concrete value without
        -- concretizing the expression.
        retval = state:regs():read(0, 4, 1)
        if retval == 0 then
            state:kill(0, "bad")
        end
    end
EOF
done
