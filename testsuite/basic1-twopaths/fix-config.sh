#!/bin/sh
set -e

echo "Patching s2e-config.lua..."

PROJECT_NAME="$(basename $PROJECT_DIR)"

if echo $PROJECT_NAME | grep -q windows; then
cat << EOF >> $PROJECT_DIR/s2e-config.lua

add_plugin("LibraryCallMonitor")
EOF
fi
