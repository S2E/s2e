#!/bin/sh
set -e

echo "Patching s2e-config.lua..."

PROJECT_NAME="$(basename $PROJECT_DIR)"

cat << EOF >> $PROJECT_DIR/s2e-config.lua

pluginsConfig.ModuleExecutionDetector = {
    mod_0 = {
        moduleName = "vmlinux",
    },

    logLevel="info"
}
EOF

cat << EOF >> $PROJECT_DIR/bootstrap.sh
${S2ECMD} flush_tbs
find /usr
EOF
