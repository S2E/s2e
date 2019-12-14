#!/bin/sh

set -e

echo "Patching s2e-config.lua..."

. ${TESTSUITE_ROOT}/helpers.sh

PROJECT_NAME="$(basename $PROJECT_DIR)"

cat << EOF >> $PROJECT_DIR/s2e-config.lua

add_plugin("FunctionMonitor")
add_plugin("LuaFunctionInstrumentation")

pluginsConfig.LuaFunctionInstrumentation = {
    instrumentation = {
    }
}

EOF

FUNCTIONS="func_a_single_path func_b func_c_single_path_nested func_d_with_fork"

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

    function $f(state, instrumentation_state, is_call)
        if is_call then
            g_s2e:debug("called $f")
        else
            g_s2e:debug("returned from $f")
        end
    end

EOF
done

# Generate config for skipped functions
FUNCTIONS="func_e_skipped"
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

    function $f(state, instrumentation_state, is_call)
        if is_call then
            g_s2e:debug("skipping $f")
            instrumentation_state:skipFunction(true)
        else
            -- This must not appear
            g_s2e:debug("returned from $f")
        end
    end
EOF
done
