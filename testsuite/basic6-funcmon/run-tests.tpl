#!/bin/bash

{% include 'common-run.sh.tpl' %}

s2e run -n {{ project_name }}

# Check that messages are in the right order for state 0
OUT="$(grep -E "\[State 0\] (called|returned)" $S2E_LAST/debug.txt | cut -d ']' -f 2)"

set +e
IFS='' read -r -d '' EXPECTED <<EOF
 called func_a_single_path
 returned from func_a_single_path
 called func_c_single_path_nested
 called func_b
 returned from func_b
 returned from func_c_single_path_nested
 called func_d_with_fork
 returned from func_d_with_fork
EOF
set -e

if [ "${OUT%$'\n'}" != "${EXPECTED%$'\n'}" ]; then
    echo "Incorrect output:"
    echo $OUT
    echo "Expected:"
    echo $EXPECTED
    exit 1
fi

# Check that the return handler is called from each forked state
OUT="$(grep -E "called func_d|returned from func_d_with_fork" $S2E_LAST/debug.txt | cut -d '[' -f 2)"
set +e
IFS='' read -r -d '' EXPECTED <<EOF
State 0] called func_d_with_fork
State 0] returned from func_d_with_fork
State 1] returned from func_d_with_fork
EOF
set -e

if [ "${OUT%$'\n'}" != "${EXPECTED%$'\n'}" ]; then
    echo "Incorrect output:"
    echo $OUT
    echo "Expected:"
    echo $EXPECTED
    exit 1
fi

# Check that skipped functions are not executed
grep -q "skipping func_e_skipped" $S2E_LAST/debug.txt
! grep -q "This message must not appear" $S2E_LAST/debug.txt

check_coverage {{project_name}} 60

s2e forkprofile {{ project_name }} > $S2E_LAST/forkprofile.txt
grep -q -i main.c $S2E_LAST/forkprofile.txt
