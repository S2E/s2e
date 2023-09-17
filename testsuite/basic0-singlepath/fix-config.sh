#!/bin/sh

set -e

echo "Patching s2e-config.lua..."

. ${TESTSUITE_ROOT}/helpers.sh

PROJECT_NAME="$(basename $PROJECT_DIR)"
TARGET_NAME="$(basename $TARGET)"

PLATFORM=$(get_platform "$TARGET")

cat << EOF >> $PROJECT_DIR/s2e-config.lua

add_plugin("EdgeDetector")
add_plugin("EdgeCoverage")

add_plugin("EdgeKiller")
pluginsConfig.EdgeKiller = {
  mod_0 = {
    l1 = {0x4016A7, 0x4016B0},
  },
}

EOF
