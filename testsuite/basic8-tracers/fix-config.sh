#!/bin/sh

set -e

echo "Patching s2e-config.lua..."

. ${TESTSUITE_ROOT}/helpers.sh

PROJECT_NAME="$(basename $PROJECT_DIR)"

PLATFORM=$(get_platform "$TARGET")

cat << EOF >> $PROJECT_DIR/s2e-config.lua

add_plugin("MemoryTracer")
pluginsConfig.MemoryTracer = {
    traceMemory = true,
    traceTlbMisses = true,
    tracePageFaults = true,
    moduleNames = {"$(basename $TARGET)"}
}

add_plugin("TranslationBlockTracer")
pluginsConfig.TranslationBlockTracer = {
    traceTbStart = true,
    traceTbEnd = true,
    moduleNames = {"$(basename $TARGET)"}
}

add_plugin("InstructionCounter")
pluginsConfig.InstructionCounter = {
    moduleNames = {"$(basename $TARGET)"}
}

EOF
