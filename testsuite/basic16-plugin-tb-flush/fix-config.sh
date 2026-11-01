#!/bin/sh

set -e

echo "Patching s2e-config.lua..."

cat << EOT >> "$PROJECT_DIR/s2e-config.lua"

add_plugin("TBCoverageTracer")
pluginsConfig.TBCoverageTracer = {
    manualTrigger = true,
    flushTbCache = true,
}
EOT
