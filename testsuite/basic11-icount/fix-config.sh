#!/bin/sh

set -e

echo "Patching s2e-config.lua..."

. ${TESTSUITE_ROOT}/helpers.sh

PROJECT_NAME="$(basename $PROJECT_DIR)"

PLATFORM=$(get_platform "$TARGET")

cat << EOF >> $PROJECT_DIR/s2e-config.lua

add_plugin("InstructionCounter")
pluginsConfig.InstructionCounter = {
    filterPlugin = "ThreadExecutionDetector"
}

add_plugin("ThreadExecutionDetector")
add_plugin("TranslationBlockTracer")
pluginsConfig.TranslationBlockTracer = {
    traceTbStart = true,
    filterPlugin = "ThreadExecutionDetector"
}

EOF
