#!/bin/bash

{% include 'common-run.sh.tpl' %}

s2e run -n {{ project_name }}

# errexit ignores a command that is inverted with "!", so this needs an explicit exit.
if grep -q "FAILED" $S2E_LAST/debug.txt; then
    exit 1
fi

echo === Checking that all paths ran
COUNT=$(grep -oE "Path [0-9]+" $S2E_LAST/debug.txt | sort -u | wc -l)
[ "$COUNT" -eq 16 ]
