#!/bin/sh

set -e

echo "Patching s2e-config.lua..."

# The guest kernel module reports the SIGTRAP of a data breakpoint as a fault of
# the process. The test expects the trap, so the state must keep running.
cat << EOT >> "$PROJECT_DIR/s2e-config.lua"

pluginsConfig.LinuxMonitor.terminateOnSegfault = false
pluginsConfig.LinuxMonitor.terminateOnTrap = false
EOT
