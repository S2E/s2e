# Copyright (C) 2017-2022, Cyberhaven
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

# Installs S2E and its associated libraries and tools to /opt/s2e

FROM ubuntu:22.04 AS s2e-build-env

# Install build dependencies.
# The unzip and libgomp1 dependencies are needed to unzip and run binary Z3
# distributions.

RUN apt-get update && dpkg --add-architecture i386 && apt-get update &&                       \
    apt-get -y install sudo git ca-certificates build-essential cmake curl wget texinfo flex bison  \
    python-is-python3 python3-dev python3-venv python3-distro mingw-w64 lsb-release \
    autoconf libtool libprotobuf-dev protobuf-compiler protobuf-c-compiler \
    libdwarf-dev libelf-dev libelf-dev:i386 \
    libboost-dev zlib1g-dev libjemalloc-dev nasm pkg-config                 \
    libmemcached-dev libpq-dev libc6-dev-i386 binutils-dev                  \
    libboost-system-dev libboost-serialization-dev libboost-regex-dev       \
    libbsd-dev libpixman-1-dev                                              \
    libglib2.0-dev libglib2.0-dev:i386 python3-docutils libpng-dev          \
    gcc-multilib g++-multilib libgomp1 unzip libzstd-dev \
    libgmock-dev libgtest-dev libsoci-dev libcapstone-dev \
    libcurl4-openssl-dev \
    libedit-dev \
    libpfm4-dev \
    llvm-14-dev \
    clang-format-14 \
    clang-14 \
    clang-15

# This scripts allows running commands as a host user inside the container.
# For example, guest tools can be built as follows:
# cd $HOME/s2e/env/source/s2e
# docker build --target s2e-build-env -t s2e-build-env .
# cd $HOME/s2e/env/build
# docker run -ti --rm -e SYSTEM_CLANG_VERSION=15 -e S2E_PREFIX="$HOME/s2e/env/install" -w $(pwd) -v $HOME:$HOME s2e-build-env /run_as.sh $(id -u) $(id -g) make  -f $HOME/s2e/env/source/s2e/Makefile.tools install
COPY scripts/run_as.sh /

###############################################################################
FROM s2e-build-env AS s2e-build-all

# Required for C++17
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common
RUN add-apt-repository ppa:ubuntu-toolchain-r/test && apt update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y gcc-9 g++-9

RUN mkdir s2e && mkdir s2e-build
COPY Makefile Makefile.tools Makefile.common s2e/

# Be explicit about not building Z3 from source, even though its default
ARG USE_Z3_BINARY=yes
ARG SYSTEM_CLANG_VERSION=15

RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2E_PREFIX=/opt/s2e stamps/z3

RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2E_PREFIX=/opt/s2e stamps/libdwarf-make

RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2E_PREFIX=/opt/s2e stamps/rapidjson-make

# Make the S2E codebase available in the container
COPY . s2e/

# Build and install everything else
RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2E_PREFIX=/opt/s2e install

RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile.tools S2E_PREFIX=/opt/s2e install
