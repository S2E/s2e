#!/bin/bash

{% include 'common-run.sh.tpl' %}

s2e run -n {{ project_name }}

echo === Checking that program did not fork
grep -q "Not equals 10" $S2E_LAST/debug.txt
! grep -q "Equals 10" $S2E_LAST/debug.txt

