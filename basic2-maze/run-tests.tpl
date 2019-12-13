#!/bin/bash

{% include 'common-run.sh.tpl' %}

s2e run -n {{ project_name }}

grep -q "You lose" $S2E_LAST/debug.txt
grep -q "You win" $S2E_LAST/debug.txt

COUNT=$(grep '\[State' "$S2E_LAST/debug.txt" | cut -d ' ' -f 3 | cut -d ']' -f 1 | sort -n | uniq | wc -l)
if [ $COUNT -ne 401 ]; then
    echo Incorrect number of states
    exit 1
fi

check_coverage {{project_name}} 70

s2e forkprofile {{ project_name }} > $S2E_LAST/forkprofile.txt
grep -q -i maze.c $S2E_LAST/forkprofile.txt
