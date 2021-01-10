#!/bin/bash

{% include 'common-run.sh.tpl' %}

timeout --foreground --kill-after=30m 29m s2e run  -n {{ project_name }}

s2e execution_trace {{ project_name }}

 TRACE="$S2E_LAST/execution_trace.json"

DCALL_COUNT=$(jq -r '[.[] | select(.type=="TRACE_CFI_STATS")][-1].direct_call_count' "$TRACE")
ICALL_COUNT=$(jq -r '[.[] | select(.type=="TRACE_CFI_STATS")][-1].indirect_call_count' "$TRACE")
RET_COUNT=$(jq -r '[.[] | select(.type=="TRACE_CFI_STATS")][-1].ret_count' "$TRACE")

if [ $DCALL_COUNT -eq 0 -o $ICALL_COUNT -eq 0 -o $RET_COUNT -eq 0 ]; then
    echo "Invalid call/ret count"
    exit 1
fi

CALL_VIOLATION_COUNT=$(jq -r '[.[] | select(.type=="TRACE_CFI_STATS")][-1].call_violation_count' "$TRACE")
RET_VIOLATION_COUNT=$(jq -r '[.[] | select(.type=="TRACE_CFI_STATS")][-1].ret_violation_count' "$TRACE")

if [ $CALL_VIOLATION_COUNT -gt 0 -o $RET_VIOLATION_COUNT -gt 0 ]; then
    echo "Invalid call/ret violation count"
    exit 1
fi
