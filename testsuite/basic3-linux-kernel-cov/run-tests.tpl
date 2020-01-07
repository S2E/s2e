#!/bin/bash

{% include 'common-run.sh.tpl' %}

s2e run -n {{ project_name }}

grep -q "All good" $S2E_LAST/debug.txt

# 2% coverage is enough
check_coverage {{project_name}} 2

if [ ! -f $S2E_LAST/vmlinux.info ]; then
    echo "Could not get linux kernel coverage"
    exit 1
fi

SOURCE_COUNT=$(grep SF $S2E_LAST/vmlinux.info | wc -l)

# Check that code coverage contains info about at least 50 source files
# (this number is arbitrary).
if [ $SOURCE_COUNT -lt 50 ]; then
    echo "Did not cover enough source files"
    exit 1
fi
