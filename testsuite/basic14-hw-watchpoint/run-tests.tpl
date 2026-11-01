#!/bin/bash

{% include 'common-run.sh.tpl' %}

s2e run -n {{ project_name }}

grep -q "All good" $S2E_LAST/debug.txt
