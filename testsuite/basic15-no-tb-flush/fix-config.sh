#!/bin/sh

set -e

echo "Patching s2e-config.lua..."

cat << EOT >> "$PROJECT_DIR/s2e-config.lua"

table.insert(s2e.kleeArgs, "--flush-tbs-on-state-switch=false")
EOT
