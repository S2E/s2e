#!/bin/bash

{% include 'common-run.sh.tpl' %}

s2e run -n {{ project_name }}

grep -q "Good" $S2E_LAST/debug.txt
! grep -q "Bad" $S2E_LAST/debug.txt

check_coverage {{project_name}} 90
