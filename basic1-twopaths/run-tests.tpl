#!/bin/bash

{% include 'common-run.sh.tpl' %}

s2e run -n {{ project_name }}

echo === Checking that program forked
grep -q "Value is 1" $S2E_LAST/debug.txt
grep -q "Value is not 1" $S2E_LAST/debug.txt

{% if 'windows' in project_name %}
echo === Checking that LibraryCallMonitor works properly
grep -q "called ntdll.dll!RtlEnterCriticalSection" $S2E_LAST/debug.txt
{% endif %}

check_coverage {{project_name}} 60

s2e forkprofile {{ project_name }} > $S2E_LAST/forkprofile.txt
grep -q -i main.c $S2E_LAST/forkprofile.txt
