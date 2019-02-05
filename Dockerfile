# Copyright (C) 2017-2019, Cyberhaven
# All rights reserved.
#
# Licensed under the Cyberhaven Research License Agreement.

# Installs S2E and its associated libraries and tools to /opt/s2e

FROM ubuntu:18.04

# Use local mirrors if possible
RUN sed -i '1ideb mirror://mirrors.ubuntu.com/mirrors.txt xenial main restricted' /etc/apt/sources.list && \
    sed -i '1ideb mirror://mirrors.ubuntu.com/mirrors.txt xenial-updates main restricted' /etc/apt/sources.list && \
    sed -i '1ideb mirror://mirrors.ubuntu.com/mirrors.txt xenial-security main restricted' /etc/apt/sources.list

# Install build dependencies
RUN dpkg --add-architecture i386 && apt-get update &&                       \
    apt-get -y install build-essential cmake wget texinfo flex bison        \
    python-dev mingw-w64 lsb-release

# Install S2E dependencies
RUN apt-get update && apt-get -y install libdwarf-dev libelf-dev libelf-dev:i386 \
    libboost-dev zlib1g-dev libjemalloc-dev nasm pkg-config                 \
    libmemcached-dev libpq-dev libc6-dev-i386 binutils-dev                  \
    libboost-system-dev libboost-serialization-dev libboost-regex-dev       \
    libbsd-dev libpixman-1-dev                                              \
    libglib2.0-dev libglib2.0-dev:i386 python-docutils libpng12-dev gcc-multilib g++-multilib

# Install S2E git
RUN apt-get -y install git

# Build LLVM first (to avoid rebuilding it for every change)
RUN mkdir s2e
RUN mkdir s2e-build
COPY build-scripts/Makefile s2e/
COPY build-scripts/determine_clang_binary_suffix.py s2e/
RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2E_PREFIX=/opt/s2e stamps/clang-binary

RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2E_PREFIX=/opt/s2e stamps/llvm-release-make

# Build S2E dependencies
RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2E_PREFIX=/opt/s2e stamps/soci-make

RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2E_PREFIX=/opt/s2e stamps/z3-make

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

# Install s2e-env
RUN apt-get -y install python-pip && \
    cd s2e/s2e-env && \
    pip install --process-dependency-links .

# Don't keep sources and build files
RUN rm -rf s2e-build s2e
