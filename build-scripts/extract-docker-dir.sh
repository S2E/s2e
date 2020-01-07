#!/bin/bash

# Copyright (C) 2017, Cyberhaven
# All rights reserved.
#
# Licensed under the Cyberhaven Research License Agreement.

set -e

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <docker_image> <docker_dir> <output_dir>"
    exit 1
fi

docker_image=$1
docker_dir=$2
output_dir=$(mkdir -p $3 && cd $3 && pwd)

docker_container=`docker run -d "$docker_image" sleep 1000`
docker cp "${docker_container}:$docker_dir" "$output_dir" || true
docker kill "$docker_container" >/dev/null || true
docker rm "$docker_container" >/dev/null
