#!/bin/bash

# Copyright (C) 2017, Cyberhaven
# All rights reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

set -e

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <docker_image> <docker_dir_or_file> <output_dir>"
    exit 1
fi

docker_image=$1
docker_dir=$2
output_dir=$(mkdir -p $3 && cd $3 && pwd)

docker_container=`docker run -d "$docker_image" sleep 1000`
docker cp "${docker_container}:$docker_dir" "$output_dir" || true
docker kill "$docker_container" >/dev/null || true
docker rm "$docker_container" >/dev/null
