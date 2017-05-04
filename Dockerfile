# Copyright (C) 2017, Cyberhaven
# All rights reserved.
#
# Licensed under the Cyberhaven Research License Agreement.

# Installs S2E and its associated libraries and tools to /opt/s2e

FROM ubuntu:16.04

# Install build dependencies
RUN apt-get update &&                                                       \
    apt-get -y install build-essential cmake wget texinfo flex bison        \
    python-dev mingw-w64 lsb-release

# Install S2E dependencies
RUN apt-get update && apt-get -y install libdwarf-dev libelf-dev            \
    libboost-dev zlib1g-dev libjemalloc-dev nasm pkg-config                 \
    libmemcached-dev libpq-dev libc6-dev-i386 libprocps4-dev                \
    libboost-system-dev libboost-serialization-dev libboost-regex-dev       \
    libprotobuf-dev protobuf-compiler libbsd-dev                            \
    libglib2.0-dev python-docutils libpng12-dev

# Install S2E git
RUN apt-get -y install git

# Build LLVM first (to avoid rebuilding it for every change)
RUN mkdir s2e
RUN mkdir s2e-build
COPY Makefile s2e/Makefile
RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2EPREFIX=/opt/s2e stamps/llvm-native-make

RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2EPREFIX=/opt/s2e stamps/llvm-release-make

# Build S2E dependencies
RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2EPREFIX=/opt/s2e stamps/soci-make

RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2EPREFIX=/opt/s2e stamps/z3-make

# Make the S2E codebase available in the container
COPY . s2e/

# Build and install everything else
RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2EPREFIX=/opt/s2e install

# Install s2e-env
RUN apt-get -y install python-pip && \
    cd s2e/s2e-env && \
    pip install .

# Don't keep sources and build files
RUN rm -rf s2e-build s2e
