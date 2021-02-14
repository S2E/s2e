#!/bin/bash

{% include 'common-run.sh.tpl' %}

timeout --foreground --kill-after=30m 25m s2e run -n {{ project_name }}

grep -q "silently concretizing" $S2E_LAST/debug.txt && exit 1

TC_COUNT=$(grep "v0_arg1_0 =" $S2E_LAST/debug.txt | wc -l)
if [ $TC_COUNT -lt 15 ]; then
    echo "Insufficient number of test cases"
    exit 1
fi
