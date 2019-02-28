#!/bin/sh
set -e

echo "Patching bootstrap.sh to start the driver..."
sed -i 's/# sc start my_driver_service/sc start scanner/g' $PROJECT_DIR/bootstrap.sh
sed -i 's/sleep 30/sleep 5/g' $PROJECT_DIR/bootstrap.sh

# Simulate DFS
echo "Patching s2e-config.lua..."
sed -i 's/batchTime = 5/batchTime = 5000/g' $PROJECT_DIR/s2e-config.lua
