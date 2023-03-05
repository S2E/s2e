#!/bin/bash

set -x

LLVM_BIN=~/s2e/env/build/llvm-release/bin

$1

"$LLVM_BIN/llvm-profdata" merge -sparse default.profraw -o default.profdata
"$LLVM_BIN/llvm-cov" show $1 --instr-profile=default.profdata -format=html -output-dir=coverage
