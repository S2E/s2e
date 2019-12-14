#!/bin/bash

{% include 'common-run.sh.tpl' %}

s2e run -n {{ project_name }}

grep -q "called scanf" "$S2E_LAST/debug.txt"
grep -q "you lost" "$S2E_LAST/debug.txt"
grep -q "you found it" "$S2E_LAST/debug.txt"
grep -q "ctf{secret-flag}" "$S2E_LAST/debug.txt"

check_coverage {{project_name}} 60

s2e forkprofile {{ project_name }} > $S2E_LAST/forkprofile.txt
grep -q -i main.c $S2E_LAST/forkprofile.txt
