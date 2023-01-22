#!/bin/bash

{% include 'common-run.sh.tpl' %}

s2e run -n {{ project_name }}

grep -q "icount good" $S2E_LAST/debug.txt

s2e execution_trace -pp {{ project_name }}
