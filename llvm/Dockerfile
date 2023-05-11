# Copyright (C) 2017-2023, Cyberhaven
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

# Generates an LLVM + Clang build that can be later used to build S2E.

# Use an older distribution for maximum compatibility.
FROM ubuntu:18.04

# Install build dependencies
RUN dpkg --add-architecture i386 && apt-get update &&                       \
    apt-get -y install ca-certificates build-essential curl wget texinfo flex bison  \
    python3-dev python3-venv python3-distro lsb-release \
    libdwarf-dev libelf-dev libelf-dev:i386 \
    zlib1g-dev nasm pkg-config                 \
    libpq-dev libc6-dev-i386 binutils-dev                  \
    libbsd-dev \
    libglib2.0-dev libglib2.0-dev:i386 python3-docutils libpng-dev          \
    gcc-multilib g++-multilib libgomp1 unzip pigz

# CMake 3.13.4 or higher is required to build LLVM 14 from source.
# Ubuntu 18.04 comes with cmake 3.10.2
# Install the latest cmake (as of this writing)
RUN wget -O cmake.sh https://github.com/Kitware/CMake/releases/download/v3.23.1/cmake-3.23.1-Linux-x86_64.sh && \
    sh ./cmake.sh --prefix=/usr/local --skip-license

RUN mkdir llvm llvm-build
COPY Makefile determine_clang_binary_suffix.py llvm/

RUN cd llvm-build && make -f ../llvm/Makefile LLVM_PREFIX=/opt/llvm release debug
