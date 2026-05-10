#!/bin/bash

{% include 'common-run.sh.tpl' %}

s2e run -n {{ project_name }}

echo === Checking that program forked 256 paths
grep -q "Byte 0 is non-zero" $S2E_LAST/debug.txt
grep -q "Byte 0 is zero" $S2E_LAST/debug.txt
grep -q "Byte 7 is non-zero" $S2E_LAST/debug.txt
grep -q "Byte 7 is zero" $S2E_LAST/debug.txt

PATH_COUNT=$(grep -c "Byte 7 is" $S2E_LAST/debug.txt)
if [ "$PATH_COUNT" -ne 256 ]; then
    echo "Expected 256 paths, got $PATH_COUNT"
    exit 1
fi

check_coverage {{project_name}} 60

s2e forkprofile {{ project_name }} > $S2E_LAST/forkprofile.txt
grep -q -i main.c $S2E_LAST/forkprofile.txt
