#!/bin/sh
set -e

sed -i 's/S2E_SYM_ARGS=""/S2E_SYM_ARGS="1"/g' "$PROJECT_DIR/bootstrap.sh"
