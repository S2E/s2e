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

FROM ubuntu:22.04

# Install build dependencies
RUN dpkg --add-architecture i386 && apt-get update &&                       \
    apt-get -y install ca-certificates build-essential curl wget texinfo flex bison  \
    python-is-python3 python3-dev python3-venv python3-distro mingw-w64 lsb-release

# Install S2E dependencies
RUN apt-get update && apt-get -y install libdwarf-dev libelf-dev libelf-dev:i386 \
    libboost-dev zlib1g-dev libjemalloc-dev nasm pkg-config                 \
    libmemcached-dev libpq-dev libc6-dev-i386 binutils-dev                  \
    libboost-system-dev libboost-serialization-dev libboost-regex-dev       \
    libbsd-dev libpixman-1-dev                                              \
    libglib2.0-dev libglib2.0-dev:i386 python3-docutils libpng-dev          \
    gcc-multilib g++-multilib libgomp1 unzip
# The unzip and libgomp1 dependencies are needed to unzip and run binary Z3
# distributions

# Required for C++17
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common
RUN add-apt-repository ppa:ubuntu-toolchain-r/test && apt update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y gcc-9 g++-9

# Install S2E git
RUN apt-get -y install git

# CMake 3.13.4 or higher is required to build LLVM-13 from source.
# Ubuntu 18.04 comes with cmake 3.10.2
# Install the latest cmake (as of this writing)
RUN wget -O cmake.sh https://github.com/Kitware/CMake/releases/download/v3.23.1/cmake-3.23.1-Linux-x86_64.sh && \
    sh ./cmake.sh --prefix=/usr/local --skip-license

# Build LLVM first (to avoid rebuilding it for every change)
RUN mkdir s2e
RUN mkdir s2e-build
COPY Makefile s2e/
COPY scripts/determine_clang_binary_suffix.py s2e/scripts/
RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2E_PREFIX=/opt/s2e stamps/clang-binary

RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2E_PREFIX=/opt/s2e stamps/llvm-release-make

# Be explicit about not building Z3 from source, even though its default
ENV USE_Z3_BINARY=yes

# Build S2E dependencies
RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2E_PREFIX=/opt/s2e stamps/soci-make

RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2E_PREFIX=/opt/s2e stamps/z3

RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2E_PREFIX=/opt/s2e stamps/protobuf-make

RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2E_PREFIX=/opt/s2e stamps/libdwarf-make

RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2E_PREFIX=/opt/s2e stamps/rapidjson-make

# Make the S2E codebase available in the container
COPY . s2e/


# Build and install everything else
RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2E_PREFIX=/opt/s2e install
