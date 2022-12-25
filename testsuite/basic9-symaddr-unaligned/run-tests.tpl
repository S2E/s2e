#!/bin/bash

{% include 'common-run.sh.tpl' %}

s2e run -n {{ project_name }}

PATH_COUNT=$(grep "Terminated symbaddr1 path" $S2E_LAST/debug.txt | wc -l)
if [ $PATH_COUNT -ne 125 ]; then
    exit 1
fi
