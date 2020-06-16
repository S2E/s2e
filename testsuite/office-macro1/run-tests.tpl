#!/bin/bash

{% include 'common-run.sh.tpl' %}

s2e run -n {{ project_name }}

grep -q "path 1" $S2E_LAST/debug.txt
grep -q "path 2" $S2E_LAST/debug.txt
