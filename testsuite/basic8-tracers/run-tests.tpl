#!/bin/bash

{% include 'common-run.sh.tpl' %}

s2e run -n {{ project_name }}

grep -q "0xdeadbeef" "$S2E_LAST/debug.txt"
grep -q "0xbadcafe" "$S2E_LAST/debug.txt"

check_coverage {{project_name}} 60

# deadbeef
s2e execution_trace -pp -p 1 {{ project_name }}
grep -q "3735928559" "$S2E_LAST/execution_trace.json"

# badcafe
s2e execution_trace -pp -p 0 {{ project_name }}
grep -q "195939070" "$S2E_LAST/execution_trace.json"

grep -q "TRACE_TB_START" "$S2E_LAST/execution_trace.json"
grep -q "TRACE_TB_END" "$S2E_LAST/execution_trace.json"
grep -q "TRACE_ICOUNT" "$S2E_LAST/execution_trace.json"

s2e forkprofile {{ project_name }} > $S2E_LAST/forkprofile.txt
grep -q -i main.c $S2E_LAST/forkprofile.txt
