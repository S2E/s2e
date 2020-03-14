#!/bin/sh
set -e

echo "Patching s2e-config.lua..."

PROJECT_NAME="$(basename $PROJECT_DIR)"

sed -i 's/kleeArgs = {/kleeArgs = { "--fork-on-symbolic-address=false"/g' "$PROJECT_DIR/s2e-config.lua"

