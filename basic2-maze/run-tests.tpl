#!/bin/bash

{% include 'common-run.sh.tpl' %}

s2e run -n {{ project_name }}

grep -q "You lose" $S2E_LAST/debug.txt
grep -q "You win" $S2E_LAST/debug.txt

echo === Computing code coverage
s2e coverage lcov --html {{ project_name }} | tee $S2E_LAST/cov.log

echo === Checking code coverage
COV_PC=$(grep "lines......" $S2E_LAST/cov.log | cut -d : -f 2 | cut -d '%' -f 1)

if (( $(bc <<< "$COV_PC < 70") )); then
    echo Bad coverage: $COV_PC
    exit 1
fi
