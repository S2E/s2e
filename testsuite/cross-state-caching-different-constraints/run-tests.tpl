#!/bin/bash

{% include 'common-run.sh.tpl' %}

s2e run -n {{ project_name }}

check_coverage {{project_name}} 100
