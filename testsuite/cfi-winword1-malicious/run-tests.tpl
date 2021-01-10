#!/bin/bash

{% include 'common-run.sh.tpl' %}

timeout --foreground --kill-after=30m 29m s2e run  -n {{ project_name }}

s2e execution_trace {{ project_name }}

TRACE="$S2E_LAST/execution_trace.json"

CALL_VIOLATION_COUNT=$(jq -r '[.[] | select(.type=="TRACE_CFI_STATS")][-1].call_violation_count' "$TRACE")
RET_VIOLATION_COUNT=$(jq -r '[.[] | select(.type=="TRACE_CFI_STATS")][-1].ret_violation_count' "$TRACE")

if [ $CALL_VIOLATION_COUNT -eq 0 -a $RET_VIOLATION_COUNT -eq 0 ]; then
    echo "Did not find any violations"
    exit 1
fi

