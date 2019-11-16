#!/bin/sh
set -e

echo "Patching s2e-config.lua..."

PROJECT_NAME="$(basename $PROJECT_DIR)"

# Frequent state switching slows down large guests, increase batch time to avoid that
sed -i 's/batchTime = 5/batchTime = 5000/g' $PROJECT_DIR/s2e-config.lua

