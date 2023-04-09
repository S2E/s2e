# Copyright (C) 2014-2023 Cyberhaven
# Copyright (C) 2010-2014 Dependable Systems Laboratory, EPFL
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

# Environment variables:
#
#  PARALLEL=no
#      Turn off build parallelization.
#
#  BUILD_ARCH=corei7, etc...
#      Overrides the default clang -march settings.
#      Useful to build LLVM in VirtualBox or in other VMs that do not support
#      some advanced instruction sets.
#

#############
# Variables #
#############

# LLVM variables
MAKEFILE_PATH?=$(dir $(realpath $(lastword $(MAKEFILE_LIST))))
LLVM_PREFIX?=$(CURDIR)/opt
LLVM_BUILD:=$(CURDIR)

# Either choose Release or RelWithDebInfo
RELEASE_BUILD_TYPE=RelWithDebInfo

BUILD_ARCH?=x86-64

CFLAGS_ARCH:=-march=$(BUILD_ARCH)
CXXFLAGS_ARCH:=-march=$(BUILD_ARCH)

CXXFLAGS_DEBUG:=$(CXXFLAGS_ARCH)
CXXFLAGS_RELEASE:=$(CXXFLAGS_ARCH)

SED:=sed

# Set the number of parallel build jobs
OS:=$(shell uname)
ifeq ($(PARALLEL), no)
JOBS:=1
else ifeq ($(OS),Darwin)
JOBS:=$(patsubst hw.ncpu:%,%,$(shell sysctl hw.ncpu))
SED:=gsed
PLATFORM:=darwin
else ifeq ($(OS),Linux)
JOBS:=$(shell grep -c ^processor /proc/cpuinfo)
PLATFORM:=linux
endif

MAKE:=make -j$(JOBS)

# LLVM variables
LLVM_BUILD?=$(LLVM_BUILD)
ifeq ($(LLVM_BUILD),$(LLVM_BUILD))
LLVM_DIRS=llvm-release llvm-debug
endif

# More recent point releases don't have the Ubuntu binaries yet, so stick with 14.0.0.
LLVM_VERSION=14.0.0
LLVM_SRC=llvm-$(LLVM_VERSION).src.tar.xz
LLVM_SRC_DIR=llvm-$(LLVM_VERSION).src
LLVM_SRC_URL=https://github.com/llvm/llvm-project/releases/download/llvmorg-$(LLVM_VERSION)/

# The Python script should only return a single word - the suffix of the Clang
# binary to download. If an error message is printed to stderr, the Makefile
# error will be triggered.
CLANG_BINARY_SUFFIX=$(shell $(MAKEFILE_PATH)/determine_clang_binary_suffix.py 2>&1)
ifneq ($(words $(CLANG_BINARY_SUFFIX)), 1)
$(error "Failed to determine Clang binary to download: $(CLANG_BINARY_SUFFIX)")
endif

CLANG_BINARY_DIR=clang+llvm-$(LLVM_VERSION)-$(CLANG_BINARY_SUFFIX)
CLANG_BINARY=$(CLANG_BINARY_DIR).tar.xz

CLANG_SRC=clang-$(LLVM_VERSION).src.tar.xz
CLANG_SRC_DIR=clang-$(LLVM_VERSION).src
CLANG_DEST_DIR=$(LLVM_SRC_DIR)/tools/clang

COMPILER_RT_SRC=compiler-rt-$(LLVM_VERSION).src.tar.xz
COMPILER_RT_SRC_DIR=compiler-rt-$(LLVM_VERSION).src
COMPILER_RT_DEST_DIR=$(LLVM_SRC_DIR)/projects/compiler-rt


###########
# Targets #
###########

release: $(LLVM_PREFIX)/release/$(CLANG_BINARY_DIR).tar.xz
debug: $(LLVM_PREFIX)/debug/$(CLANG_BINARY_DIR).tar.xz

ALWAYS:

$(LLVM_DIRS) stamps:
	mkdir -p $@

stamps/%-configure: | % stamps
	cd $* && $(CONFIGURE_COMMAND)
	touch $@

stamps/%-make:
	$(MAKE) -C $* $(BUILD_OPTS)
	touch $@

#############
# Downloads #
#############

define DOWNLOAD
curl -f -L "$1" -o "$2"
endef


# Download LLVM
$(LLVM_SRC) $(CLANG_SRC) $(COMPILER_RT_SRC) $(CLANG_BINARY):
	$(call DOWNLOAD,$(LLVM_SRC_URL)/$@,$@)


.INTERMEDIATE: $(CLANG_SRC_DIR) $(COMPILER_RT_SRC_DIR) $(CLANG_BINARY_DIR)

$(LLVM_SRC_DIR): $(LLVM_SRC) $(CLANG_SRC_DIR) $(COMPILER_RT_SRC_DIR)
	tar -xmf $<
	mv $(CLANG_SRC_DIR) $(CLANG_DEST_DIR)
	mv $(COMPILER_RT_SRC_DIR) $(COMPILER_RT_DEST_DIR)

$(CLANG_SRC_DIR): $(CLANG_SRC)
	tar -xmf $<

$(COMPILER_RT_SRC_DIR): $(COMPILER_RT_SRC)
	tar -xmf $<


########
# LLVM #
########

stamps/clang-binary: $(CLANG_BINARY) | stamps
	tar -xmf $<
	mkdir -p $(LLVM_PREFIX)
	cp -r $(CLANG_BINARY_DIR)/* $(LLVM_PREFIX)
	rm -r $(CLANG_BINARY_DIR)/*
	touch $@

CLANG_CC = $(LLVM_PREFIX)/bin/clang
CLANG_CXX = $(LLVM_PREFIX)/bin/clang++
CLANG_LIB = $(LLVM_PREFIX)/lib

LLVM_CONFIGURE_FLAGS = -DLLVM_TARGETS_TO_BUILD="X86"        \
                       -DLLVM_TARGET_ARCH="X86_64"          \
                       -DLLVM_INCLUDE_EXAMPLES=Off          \
                       -DLLVM_INCLUDE_DOCS=Off              \
                       -DLLVM_INCLUDE_TESTS=On              \
                       -DLLVM_ENABLE_RTTI=On                \
                       -DLLVM_ENABLE_EH=On                  \
                       -DLLVM_INCLUDE_BENCHMARKS=Off        \
                       -DLLVM_BINUTILS_INCDIR=/usr/include  \
                       -DCOMPILER_RT_BUILD_SANITIZERS=Off   \
                       -DENABLE_ASSERTIONS=On               \
                       -DCMAKE_C_COMPILER=$(CLANG_CC)       \
                       -DCMAKE_CXX_COMPILER=$(CLANG_CXX)    \
                       -DCMAKE_C_FLAGS="$(CFLAGS_ARCH)"     \
                       -G "Unix Makefiles"

stamps/llvm-debug-configure: stamps/clang-binary $(LLVM_SRC_DIR)
stamps/llvm-debug-configure: CONFIGURE_COMMAND = cmake $(LLVM_CONFIGURE_FLAGS)         \
                                                 -DCMAKE_BUILD_TYPE=Debug              \
                                                 -DCMAKE_CXX_FLAGS="$(CXXFLAGS_DEBUG)" \
												 -DCMAKE_INSTALL_PREFIX="$(LLVM_PREFIX)/debug/$(CLANG_BINARY_DIR)" \
                                                 $(LLVM_BUILD)/$(LLVM_SRC_DIR)

stamps/llvm-release-configure: stamps/clang-binary $(LLVM_SRC_DIR)
stamps/llvm-release-configure: CONFIGURE_COMMAND = cmake $(LLVM_CONFIGURE_FLAGS)           \
                                                   -DCMAKE_BUILD_TYPE=$(RELEASE_BUILD_TYPE)  \
                                                   -DCMAKE_CXX_FLAGS="$(CXXFLAGS_RELEASE)" \
												   -DCMAKE_INSTALL_PREFIX="$(LLVM_PREFIX)/release/$(CLANG_BINARY_DIR)" \
                                                   $(LLVM_BUILD)/$(LLVM_SRC_DIR)

stamps/llvm-debug-make: stamps/llvm-debug-configure

stamps/llvm-release-make: stamps/llvm-release-configure

stamps/llvm-release-install: stamps/llvm-release-make
	cd $(LLVM_BUILD)/llvm-release && make install
	-cd $(LLVM_PREFIX)/release/$(CLANG_BINARY_DIR)/bin && strip *
	cp $(LLVM_BUILD)/llvm-release/lib/LLVMgold.so $(LLVM_PREFIX)/release/$(CLANG_BINARY_DIR)/lib

stamps/llvm-debug-install: stamps/llvm-debug-make
	cd $(LLVM_BUILD)/llvm-debug && make install
	-cd $(LLVM_PREFIX)/debug/$(CLANG_BINARY_DIR)/bin && strip *
	cp $(LLVM_BUILD)/llvm-debug/lib/LLVMgold.so $(LLVM_PREFIX)/debug/$(CLANG_BINARY_DIR)/lib

$(LLVM_PREFIX)/release/$(CLANG_BINARY_DIR).tar.xz: stamps/llvm-release-install
	cd $(LLVM_PREFIX)/release && tar -I "xz -T 0" -cf "$(shell basename $@)" $(CLANG_BINARY_DIR)

$(LLVM_PREFIX)/debug/$(CLANG_BINARY_DIR).tar.xz: stamps/llvm-debug-install
	cd $(LLVM_PREFIX)/debug && tar -I "xz -T 0" -cf "$(shell basename $@)" $(CLANG_BINARY_DIR)
