#!/bin/bash

{% include 'common-run.sh.tpl' %}

s2e run -n {{ project_name }}

echo === Checking that faults were injected
grep -q "FaultInjInvokeOrig_ZwOpenKey" $S2E_LAST/debug.txt
grep -q "FaultInjInvokeOrig_ExAllocatePoolWithTag" $S2E_LAST/debug.txt

check_coverage {{project_name}} 50 "{{ test_dir }}/scanner"

s2e forkprofile {{ project_name }} > $S2E_LAST/forkprofile.txt
grep -q -i s2e.sys $S2E_LAST/forkprofile.txt
