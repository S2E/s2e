#!/bin/bash

{% include 'common-run.sh.tpl' %}

s2e run -n {{ project_name }}

# Make sure this test case generates exactly 4 states.
grep -q "This is state 0 here" $S2E_LAST/debug.txt
grep -q "This is state 1 here" $S2E_LAST/debug.txt
grep -q "This is state 2 here" $S2E_LAST/debug.txt
grep -q "This is state 3 here" $S2E_LAST/debug.txt

check_coverage {{project_name}} 100.0
