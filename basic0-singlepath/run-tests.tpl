#!/bin/bash

{% include 'common-run.sh.tpl' %}

s2e run -n {{ project_name }}

grep -q "All good" $S2E_LAST/debug.txt

echo === Computing code coverage
s2e coverage lcov --html {{ project_name }} | tee $S2E_LAST/cov.log

echo === Checking code coverage
COV_PC=$(grep "lines......" $S2E_LAST/cov.log | cut -d : -f 2 | cut -d '%' -f 1)

if (( $(bc <<< "$COV_PC < 100") )); then
    echo Bad coverage: $COV_PC
    exit 1
fi
