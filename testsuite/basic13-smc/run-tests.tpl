#!/bin/bash

{% include 'common-run.sh.tpl' %}

s2e run -n {{ project_name }}

grep -q "All good" $S2E_LAST/debug.txt

echo === Checking that the KLEE cases did run in KLEE
LLVM_TBS=$(tail -n 1 $S2E_LAST/stats.csv | cut -d , -f 2)
[ "$LLVM_TBS" -gt 0 ]
