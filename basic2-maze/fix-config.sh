#!/bin/sh
set -e

echo "Patching s2e-config.lua..."

# Frequent state switching slows down large guests, increase batch time to avoid that
sed -i 's/batchTime = 5/batchTime = 5000/g' $PROJECT_DIR/s2e-config.lua

# Make sed worked
grep -q "batchTime = 5000" $PROJECT_DIR/s2e-config.lua
