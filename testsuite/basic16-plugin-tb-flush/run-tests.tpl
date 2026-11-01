#!/bin/bash

{% include 'common-run.sh.tpl' %}

s2e run -n {{ project_name }}

grep -q "All good" $S2E_LAST/debug.txt

echo === Checking that the plugin received the commands
[ "$(grep -c "enabling tracing" $S2E_LAST/debug.txt)" -eq 2 ]
[ "$(grep -c "disabling tracing" $S2E_LAST/debug.txt)" -eq 2 ]
