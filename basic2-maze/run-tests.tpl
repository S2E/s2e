#!/bin/bash

{% include 'common-run.sh.tpl' %}

s2e run -n {{ project_name }}

grep -q "You lose" $S2E_LAST/debug.txt
grep -q "You win" $S2E_LAST/debug.txt

check_coverage {{project_name}} 70

s2e forkprofile {{ project_name }} > $S2E_LAST/forkprofile.txt
grep -q -i maze.c $S2E_LAST/forkprofile.txt
