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
#      Useful to build S2E in VirtualBox or in other VMs that do not support
#      some advanced instruction sets.
#
#  LLVM_BUILD=...
#      Contains llvm-release, llvm-debug, and llvm source folders
#      Can be used to avoid rebuilding clang/llvm for every branch of S2E
#
#  USE_Z3_BINARY=yes
#      Whether to use the Z3 binary or to build Z3 from source
#

# Check the build directory
ifeq ($(shell ls libs2e/src/libs2e.c 2>&1),libs2e/src/libs2e.c)
    $(error You should not run make in the S2E source directory!)
endif

#############
# Variables #
#############

# S2E variables
BUILD_SCRIPTS_SRC?=$(dir $(realpath $(lastword $(MAKEFILE_LIST))))/scripts
S2E_SRC?=$(realpath $(BUILD_SCRIPTS_SRC)/../)
S2E_PREFIX?=$(CURDIR)/opt
S2E_BUILD:=$(CURDIR)


# Build Z3 from binary (default, "yes") or source ("no")
USE_Z3_BINARY?=yes

# Either choose Release or RelWithDebInfo
RELEASE_BUILD_TYPE=RelWithDebInfo

# corei7 avoids instructions not supported by VirtualBox. Use "native" instead
# to optimize for your current CPU.
BUILD_ARCH?=native

CFLAGS_ARCH:=-march=$(BUILD_ARCH)
CXXFLAGS_ARCH:=-march=$(BUILD_ARCH)

CXXFLAGS_DEBUG:=$(CXXFLAGS_ARCH) -fno-limit-debug-info
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

FIND_SOURCE=$(shell find $(1) -name '*.cpp' -o -name '*.h' -o -name '*.c')
FIND_CONFIG_SOURCE=$(shell find $(1) -name 'configure' -o -name 'CMakeLists.txt' -o -name '*.in')

# TODO: figure out how to automatically get the latest version without
# having to update this URL.
GUEST_TOOLS_BINARIES_URL=https://github.com/S2E/s2e/releases/download/v2.0.0/

# LLVM variables
LLVM_BUILD?=$(S2E_BUILD)
ifeq ($(LLVM_BUILD),$(S2E_BUILD))
LLVM_DIRS=llvm-release llvm-debug
endif

CLANG_LLVM=clang+llvm-14.0.0-x86_64-linux-gnu-ubuntu-18.04
CLANG_LLVM_DEBUG_ARCHIVE=$(CLANG_LLVM)-debug.tar.xz
CLANG_LLVM_DEBUG_URL=https://github.com/S2E/s2e/releases/download/v2.0.0/$(CLANG_LLVM_DEBUG_ARCHIVE)

CLANG_LLVM_RELEASE_ARCHIVE=$(CLANG_LLVM)-release.tar.xz
CLANG_LLVM_RELEASE_URL=https://github.com/S2E/s2e/releases/download/v2.0.0/$(CLANG_LLVM_RELEASE_ARCHIVE)


KLEE_DIRS=$(foreach suffix,-debug -release -coverage,$(addsuffix $(suffix),klee))

# Z3 variables
Z3_VERSION=4.7.1
Z3_SRC=z3-$(Z3_VERSION).tar.gz
Z3_SRC_DIR=z3-z3-$(Z3_VERSION)
Z3_BUILD_DIR=z3
Z3_URL=https://github.com/Z3Prover/z3
Z3_BINARY_URL=https://github.com/Z3Prover/z3/releases/download/z3-$(Z3_VERSION)/
Z3_BINARY=z3-$(Z3_VERSION)-x64-ubuntu-16.04.zip
Z3_BINARY_DIR=z3-$(Z3_VERSION)-x64-ubuntu-16.04

# Lua variables
LUA_VERSION=5.4.6
LUA_SRC=lua-$(LUA_VERSION).tar.gz
LUA_DIR=lua-$(LUA_VERSION)

# libdwarf
# We don't use the one that ships with the distro because we need
# the latest features (PE file support mostly).
LIBDWARF_URL=https://github.com/S2E/s2e/releases/download/v2.0.0/libdwarf-0.9.1.tar.xz
LIBDWARF_SRC_DIR=libdwarf-0.9.1
LIBDWARF_BUILD_DIR=libdwarf


###########
# Targets #
###########

all: all-release guest-tools

all-release: stamps/libs2e-release-make stamps/tools-release-make
all-debug: stamps/libs2e-debug-make stamps/tools-debug-make

guest-tools: stamps/guest-tools32-make stamps/guest-tools64-make
guest-tools-win: stamps/guest-tools32-win-make stamps/guest-tools64-win-make

guest-tools-install: stamps/guest-tools32-install stamps/guest-tools64-install
guest-tools-win-install: stamps/guest-tools32-win-install stamps/guest-tools64-win-install

install: all-release stamps/libs2e-release-install stamps/tools-release-install \
    stamps/libvmi-release-install guest-tools-install     \
    guest-tools-win-install
install-debug: all-debug stamps/libs2e-debug-install stamps/tools-debug-install \
    stamps/libvmi-debug-install guest-tools-install       \
    guest-tools-win-install

# From https://stackoverflow.com/questions/4219255/how-do-you-get-the-list-of-targets-in-a-makefile
list:
	@$(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null |                                  \
		awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' | \
		sort | egrep -v -e '^[^[:alnum:]]' -e '^$@$$' | xargs

.PHONY: all all-debug all-release
.PHONY: clean distclean guestclean
.PHONY: list

ALWAYS:

$(KLEE_DIRS) $(LLVM_DIRS) libq-debug libq-release                   \
libfsigc++-debug libfsigc++-release libvmi-debug libvmi-release     \
libcoroutine-release libcoroutine-debug libs2e-debug libs2e-release \
tools-debug tools-release                                           \
guest-tools32 guest-tools64 guest-tools32-win guest-tools64-win     \
stamps:
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
$(CLANG_LLVM_DEBUG_ARCHIVE):
	$(call DOWNLOAD,$(CLANG_LLVM_DEBUG_URL),$@)

$(CLANG_LLVM_RELEASE_ARCHIVE):
	$(call DOWNLOAD,$(CLANG_LLVM_RELEASE_URL),$@)

# Download Lua
$(LUA_SRC):
	$(call DOWNLOAD,https://github.com/S2E/s2e/releases/download/v2.0.0/$(LUA_SRC),$@)

$(LUA_DIR): | $(LUA_SRC)
	tar -zxf $(LUA_SRC)

# Download Z3
$(Z3_BUILD_DIR):
	$(call DOWNLOAD,$(Z3_URL)/archive/$(Z3_SRC),$(Z3_SRC))
	tar -zxf $(Z3_SRC)
	mkdir -p $(S2E_BUILD)/$(Z3_BUILD_DIR)

$(LIBDWARF_BUILD_DIR):
	$(call DOWNLOAD,$(LIBDWARF_URL),$(S2E_BUILD)/$(LIBDWARF_BUILD_DIR).tar.gz)
	tar -Jxf $(S2E_BUILD)/$(LIBDWARF_BUILD_DIR).tar.gz
	mkdir -p $(S2E_BUILD)/$(LIBDWARF_BUILD_DIR)

########
# LLVM #
########
stamps/llvm-release-make: $(CLANG_LLVM_RELEASE_ARCHIVE) | stamps
	mkdir -p "$(S2E_BUILD)/llvm-release"
	tar -Jxf $< --transform s/$(CLANG_LLVM)/llvm-release/
	touch $@

stamps/llvm-debug-make: $(CLANG_LLVM_DEBUG_ARCHIVE) | stamps
	mkdir -p "$(S2E_BUILD)/llvm-debug"
	tar -Jxf $< --transform s/$(CLANG_LLVM)/llvm-debug/
	touch $@

CLANG_CC=$(S2E_BUILD)/llvm-release/bin/clang
CLANG_CXX=$(S2E_BUILD)/llvm-release/bin/clang++
CLANG_LIB=$(S2E_BUILD)/llvm-release/lib

######
# Z3 #
######

Z3_CONFIGURE_FLAGS = -DCMAKE_INSTALL_PREFIX=$(S2E_PREFIX)               \
                     -DCMAKE_C_COMPILER=$(CLANG_CC)                     \
                     -DCMAKE_CXX_COMPILER=$(CLANG_CXX)                  \
                     -DCMAKE_C_FLAGS="-fno-omit-frame-pointer -fPIC"    \
                     -DCMAKE_CXX_FLAGS="-fno-omit-frame-pointer -fPIC"  \
                     -DBUILD_LIBZ3_SHARED=Off                           \
                     -DUSE_OPENMP=Off                                   \
                     -G "Unix Makefiles"

stamps/z3-configure: stamps/llvm-release-make $(Z3_BUILD_DIR)
	cd $(Z3_SRC_DIR) &&                                         \
	python3 contrib/cmake/bootstrap.py create
	cd $(Z3_BUILD_DIR) &&                                       \
	cmake $(Z3_CONFIGURE_FLAGS) $(S2E_BUILD)/$(Z3_SRC_DIR)
	touch $@

stamps/z3-make: stamps/z3-configure
	$(MAKE) -C $(Z3_BUILD_DIR)
	$(MAKE) -C $(Z3_BUILD_DIR) install
	touch $@

$(Z3_BINARY):
	$(call DOWNLOAD,$(Z3_BINARY_URL)/$@,$@)

stamps/z3-binary: $(Z3_BINARY) | stamps
	unzip -qqo $<
	mkdir -p $(S2E_PREFIX)
	mkdir -p $(S2E_PREFIX)/include
	mkdir -p $(S2E_PREFIX)/lib
	mkdir -p $(S2E_PREFIX)/bin
	cp -r $(Z3_BINARY_DIR)/include/* $(S2E_PREFIX)/include/
	cp $(Z3_BINARY_DIR)/bin/*.a $(S2E_PREFIX)/lib/
	cp $(Z3_BINARY_DIR)/bin/z3 $(S2E_PREFIX)/bin/
	rm -r $(Z3_BINARY_DIR)/*
	touch $@

ifeq ($(USE_Z3_BINARY),no)
stamps/z3: stamps/z3-make
	touch $@
else
stamps/z3: stamps/z3-binary
	touch $@
endif

############
# libdwarf #
############

stamps/libdwarf-configure: stamps/llvm-release-make $(LIBDWARF_BUILD_DIR)
	cd $(LIBDWARF_BUILD_DIR) &&                                         \
	CC=$(CLANG_CC) CXX=$(CLANG_CXX) $(S2E_BUILD)/$(LIBDWARF_SRC_DIR)/configure --prefix=$(S2E_PREFIX)
	touch $@

stamps/libdwarf-make: stamps/libdwarf-configure
	$(MAKE) -C $(LIBDWARF_BUILD_DIR)
	$(MAKE) -C $(LIBDWARF_BUILD_DIR) install
	touch $@

#######
# Lua #
#######

stamps/lua-make: $(LUA_DIR)
	if [ "$(PLATFORM)" = "linux" ]; then \
		$(MAKE) -C $^ linux CFLAGS="-DLUA_USE_LINUX -O2 -g -fPIC"; \
	elif [ "$(PLATFORM)" = "darwin" ]; then \
		$(MAKE) -C $^ macosx CFLAGS="-DLUA_USE_LINUX -O2 -g -fPIC"; \
	fi
	touch $@


########
# KLEE #
########

KLEE_CONFIGURE_FLAGS = -DCMAKE_INSTALL_PREFIX=$(S2E_PREFIX)                                 \
                       -DCMAKE_C_FLAGS="$(CFLAGS_ARCH) -fno-omit-frame-pointer -fPIC"       \
                       -DCMAKE_C_COMPILER=$(CLANG_CC)                                       \
                       -DCMAKE_CXX_COMPILER=$(CLANG_CXX)                                    \
                       -DENABLE_UNIT_TESTS=On                                               \
                       -DENABLE_DOCS=Off                                                    \
                       -DENABLE_SOLVER_Z3=On                                                \
                       -DZ3_INCLUDE_DIRS=$(S2E_PREFIX)/include                              \
                       -DZ3_LIBRARIES=$(S2E_PREFIX)/lib/libz3.a

stamps/klee-debug-configure: stamps/llvm-debug-make stamps/z3 $(call FIND_CONFIG_SOURCE,$(S2E_SRC)/klee)
stamps/klee-debug-configure: CONFIGURE_COMMAND = cmake $(KLEE_CONFIGURE_FLAGS)                      \
                                                 -DCMAKE_BUILD_TYPE=Debug                           \
                                                 -DLLVM_DIR=$(LLVM_BUILD)/llvm-debug/lib/cmake/llvm \
                                                 -DCMAKE_CXX_FLAGS="$(CXXFLAGS_DEBUG) -fno-omit-frame-pointer -fPIC" \
                                                 $(S2E_SRC)/klee

stamps/klee-coverage-configure: stamps/llvm-debug-make stamps/z3 $(call FIND_CONFIG_SOURCE,$(S2E_SRC)/klee)
stamps/klee-coverage-configure: CONFIGURE_COMMAND = cmake $(KLEE_CONFIGURE_FLAGS)                      \
                                                 -DCMAKE_BUILD_TYPE=Debug                           \
                                                 -DLLVM_DIR=$(LLVM_BUILD)/llvm-debug/lib/cmake/llvm \
                                                 -DCMAKE_CXX_FLAGS="$(CXXFLAGS_DEBUG) -fno-omit-frame-pointer -fPIC -fprofile-instr-generate -fcoverage-mapping" \
                                                 $(S2E_SRC)/klee

stamps/klee-release-configure: stamps/llvm-release-make stamps/z3 $(call FIND_CONFIG_SOURCE,$(S2E_SRC)/klee)
stamps/klee-release-configure: CONFIGURE_COMMAND = cmake $(KLEE_CONFIGURE_FLAGS)                        \
                                                   -DCMAKE_BUILD_TYPE=$(RELEASE_BUILD_TYPE)             \
                                                   -DLLVM_DIR=$(LLVM_BUILD)/llvm-release/lib/cmake/llvm \
                                                   -DCMAKE_CXX_FLAGS="$(CXXFLAGS_RELEASE) -fno-omit-frame-pointer -fPIC" \
                                                   $(S2E_SRC)/klee

stamps/klee-debug-make: stamps/klee-debug-configure $(call FIND_SOURCE,$(S2E_SRC)/klee)

stamps/klee-coverage-make: stamps/klee-coverage-configure $(call FIND_SOURCE,$(S2E_SRC)/klee)

stamps/klee-release-make: stamps/klee-release-configure $(call FIND_SOURCE,$(S2E_SRC)/klee)

##########
# LibVMI #
##########

LIBVMI_COMMON_FLAGS = -DCMAKE_INSTALL_PREFIX=$(S2E_PREFIX)          \
                      -DCMAKE_MODULE_PATH=$(S2E_SRC)/cmake          \
                      -DCMAKE_C_COMPILER=$(CLANG_CC)                \
                      -DCMAKE_CXX_COMPILER=$(CLANG_CXX)             \
                      -DCMAKE_C_FLAGS="$(CFLAGS_ARCH) -fPIC"        \
                      -G "Unix Makefiles"

stamps/libvmi-debug-configure: stamps/llvm-debug-make stamps/libdwarf-make $(call FIND_CONFIG_SOURCE,$(S2E_SRC)/libvmi)
stamps/libvmi-debug-configure: CONFIGURE_COMMAND = cmake $(LIBVMI_COMMON_FLAGS)                         \
                                                   -DLLVM_DIR=$(LLVM_BUILD)/llvm-debug/lib/cmake/llvm   \
                                                   -DCMAKE_BUILD_TYPE=Debug                             \
                                                   -DCMAKE_CXX_FLAGS="$(CXXFLAGS_DEBUG) -fPIC"          \
                                                   $(S2E_SRC)/libvmi

stamps/libvmi-release-configure: stamps/llvm-release-make stamps/libdwarf-make $(call FIND_CONFIG_SOURCE,$(S2E_SRC)/libvmi)
stamps/libvmi-release-configure: CONFIGURE_COMMAND = cmake $(LIBVMI_COMMON_FLAGS)                           \
                                                     -DLLVM_DIR=$(LLVM_BUILD)/llvm-release/lib/cmake/llvm   \
                                                     -DCMAKE_BUILD_TYPE=$(RELEASE_BUILD_TYPE)               \
                                                     -DCMAKE_CXX_FLAGS="$(CXXFLAGS_RELEASE) -fPIC"          \
                                                     $(S2E_SRC)/libvmi

stamps/libvmi-debug-make: stamps/libvmi-debug-configure $(call FIND_SOURCE,$(S2E_SRC)/libvmi)

stamps/libvmi-release-make: stamps/libvmi-release-configure $(call FIND_SOURCE,$(S2E_SRC)/libvmi)

stamps/libvmi-debug-install: stamps/libvmi-debug-make
	$(MAKE) -C libvmi-debug install
	touch $@

stamps/libvmi-release-install: stamps/libvmi-release-make
	$(MAKE) -C libvmi-release install
	touch $@

##############
# libfsigc++ #
##############

#TODO: factor out common flags

LIBFSIGCXX_COMMON_FLAGS = -DCMAKE_MODULE_PATH=$(S2E_SRC)/cmake  \
                          -DCMAKE_C_COMPILER=$(CLANG_CC)        \
                          -DCMAKE_CXX_COMPILER=$(CLANG_CXX)     \
                          -DCMAKE_C_FLAGS="$(CFLAGS_ARCH)"      \
                          -G "Unix Makefiles"

stamps/libfsigc++-debug-configure: stamps/llvm-release-make $(call FIND_CONFIG_SOURCE,$(S2E_SRC)/libfsigc++)

stamps/libfsigc++-debug-configure: CONFIGURE_COMMAND = cmake $(LIBFSIGCXX_COMMON_FLAGS) \
                                                       -DCMAKE_BUILD_TYPE=Debug         \
                                                       -DCMAKE_CXX_FLAGS="$(CXXFLAGS_DEBUG)" \
                                                       $(S2E_SRC)/libfsigc++


stamps/libfsigc++-release-configure: stamps/llvm-release-make $(call FIND_CONFIG_SOURCE,$(S2E_SRC)/libfsigc++)

stamps/libfsigc++-release-configure: CONFIGURE_COMMAND = cmake $(LIBFSIGCXX_COMMON_FLAGS)   \
                                     -DCMAKE_BUILD_TYPE=$(RELEASE_BUILD_TYPE)               \
                                     -DCMAKE_CXX_FLAGS="$(CXXFLAGS_RELEASE)"                \
                                     $(S2E_SRC)/libfsigc++

stamps/libfsigc++-debug-make: stamps/libfsigc++-debug-configure $(call FIND_SOURCE,$(S2E_SRC)/libfsigc++)

stamps/libfsigc++-release-make: stamps/libfsigc++-release-configure $(call FIND_SOURCE,$(S2E_SRC)/libfsigc++)

########
# libq #
########

LIBQ_COMMON_FLAGS = -DCMAKE_MODULE_PATH=$(S2E_SRC)/cmake    \
                    -DCMAKE_C_COMPILER=$(CLANG_CC)          \
                    -DCMAKE_CXX_COMPILER=$(CLANG_CXX)       \
                    -DCMAKE_C_FLAGS="$(CFLAGS_ARCH)"        \
                    -G "Unix Makefiles"

stamps/libq-debug-configure: stamps/llvm-release-make $(call FIND_CONFIG_SOURCE,$(S2E_SRC)/libq)

stamps/libq-debug-configure: CONFIGURE_COMMAND = cmake $(LIBQ_COMMON_FLAGS) \
                                                 -DCMAKE_BUILD_TYPE=Debug   \
                                                 -DCMAKE_CXX_FLAGS="$(CXXFLAGS_DEBUG)" \
                                                 $(S2E_SRC)/libq


stamps/libq-release-configure: stamps/llvm-release-make $(call FIND_CONFIG_SOURCE,$(S2E_SRC)/libq)

stamps/libq-release-configure: CONFIGURE_COMMAND = cmake $(LIBQ_COMMON_FLAGS)                 \
                                                   -DCMAKE_BUILD_TYPE=$(RELEASE_BUILD_TYPE)   \
                                                   -DCMAKE_CXX_FLAGS="$(CXXFLAGS_RELEASE)"    \
                                                   $(S2E_SRC)/libq

stamps/libq-debug-make: stamps/libq-debug-configure $(call FIND_SOURCE,$(S2E_SRC)/libq)

stamps/libq-release-make: stamps/libq-release-configure $(call FIND_SOURCE,$(S2E_SRC)/libq)

################
# libcoroutine #
################

LIBCOROUTINE_COMMON_FLAGS = -DCMAKE_MODULE_PATH=$(S2E_SRC)/cmake    \
                            -DCMAKE_C_COMPILER=$(CLANG_CC)          \
                            -DCMAKE_CXX_COMPILER=$(CLANG_CXX)       \
                            -DCMAKE_C_FLAGS="$(CFLAGS_ARCH)"        \
                            -G "Unix Makefiles"

stamps/libcoroutine-debug-configure: stamps/llvm-release-make $(call FIND_CONFIG_SOURCE,$(S2E_SRC)/libcoroutine)

stamps/libcoroutine-debug-configure: CONFIGURE_COMMAND = cmake $(LIBCOROUTINE_COMMON_FLAGS)    \
                                                         -DCMAKE_BUILD_TYPE=Debug              \
                                                         -DCMAKE_CXX_FLAGS="$(CXXFLAGS_DEBUG)" \
                                                         $(S2E_SRC)/libcoroutine


stamps/libcoroutine-release-configure: stamps/llvm-release-make $(call FIND_CONFIG_SOURCE,$(S2E_SRC)/libcoroutine)

stamps/libcoroutine-release-configure: CONFIGURE_COMMAND = cmake $(LIBCOROUTINE_COMMON_FLAGS)        \
                                                           -DCMAKE_BUILD_TYPE=$(RELEASE_BUILD_TYPE)  \
                                                           -DCMAKE_CXX_FLAGS="$(CXXFLAGS_RELEASE)"   \
                                                           $(S2E_SRC)/libcoroutine

stamps/libcoroutine-debug-make: stamps/libcoroutine-debug-configure $(call FIND_SOURCE,$(S2E_SRC)/libcoroutine)

stamps/libcoroutine-release-make: stamps/libcoroutine-release-configure $(call FIND_SOURCE,$(S2E_SRC)/libcoroutine)


##########
# libs2e #
##########

LIBS2E_CONFIGURE_FLAGS = --with-cc=$(CLANG_CC)                                      \
                         --with-cxx=$(CLANG_CXX)                                    \
                         --with-cflags=$(CFLAGS_ARCH)                               \
                         --with-liblua=$(S2E_BUILD)/$(LUA_DIR)/src                  \
                         --with-s2e-guest-incdir=$(S2E_SRC)/guest/common/include    \
                         --with-z3-incdir=$(S2E_PREFIX)/include                     \
                         --with-z3-libdir=$(S2E_PREFIX)/lib                         \
                         --with-libtcg-src=$(S2E_SRC)/libtcg                        \
                         --with-libcpu-src=$(S2E_SRC)/libcpu                        \
                         --with-libs2ecore-src=$(S2E_SRC)/libs2ecore                \
                         --with-libs2eplugins-src=$(S2E_SRC)/libs2eplugins          \
                         --prefix=$(S2E_PREFIX)                                     \

LIBS2E_DEBUG_FLAGS = --with-llvm=$(LLVM_BUILD)/llvm-debug                           \
                     --with-klee=$(S2E_BUILD)/klee-debug                            \
                     --with-libvmi=$(S2E_BUILD)/libvmi-debug                        \
                     --with-fsigc++=$(S2E_BUILD)/libfsigc++-debug                   \
                     --with-libq=$(S2E_BUILD)/libq-debug                            \
                     --with-libcoroutine=$(S2E_BUILD)/libcoroutine-debug            \
                     --with-cxxflags="$(CXXFLAGS_DEBUG)"                            \
                     --enable-debug

LIBS2E_RELEASE_FLAGS = --with-llvm=$(LLVM_BUILD)/llvm-release                       \
                       --with-klee=$(S2E_BUILD)/klee-release                        \
                       --with-libvmi=$(S2E_BUILD)/libvmi-release                    \
                       --with-fsigc++=$(S2E_BUILD)/libfsigc++-release               \
                       --with-libq=$(S2E_BUILD)/libq-release                        \
                       --with-libcoroutine=$(S2E_BUILD)/libcoroutine-release        \
                       --with-cxxflags="$(CXXFLAGS_RELEASE)"

stamps/libs2e-debug-configure: $(call FIND_CONFIG_SOURCE,$(S2E_SRC)/libs2e)
stamps/libs2e-debug-configure: stamps/lua-make stamps/libvmi-debug-install      \
    stamps/klee-debug-make stamps/libfsigc++-debug-make        \
    stamps/libq-debug-make stamps/libcoroutine-debug-make  \
    stamps/klee-coverage-make
stamps/libs2e-debug-configure: CONFIGURE_COMMAND = $(S2E_SRC)/libs2e/configure  \
                                                   $(LIBS2E_CONFIGURE_FLAGS)    \
                                                   $(LIBS2E_DEBUG_FLAGS)

stamps/libs2e-release-configure: $(call FIND_CONFIG_SOURCE,$(S2E_SRC)/libs2e)
stamps/libs2e-release-configure: stamps/lua-make stamps/libvmi-release-install  \
    stamps/klee-release-make stamps/libfsigc++-release-make    \
    stamps/libq-release-make stamps/libcoroutine-release-make

stamps/libs2e-release-configure: CONFIGURE_COMMAND = $(S2E_SRC)/libs2e/configure    \
                                                     $(LIBS2E_CONFIGURE_FLAGS)      \
                                                     $(LIBS2E_RELEASE_FLAGS)

stamps/libs2e-debug-make: stamps/libs2e-debug-configure \
	$(call FIND_SOURCE,$(S2E_SRC)/libs2e) \
	$(call FIND_SOURCE,$(S2E_SRC)/libcpu) \
	$(call FIND_SOURCE,$(S2E_SRC)/libtcg) \
	$(call FIND_SOURCE,$(S2E_SRC)/libs2ecore) \
	$(call FIND_SOURCE,$(S2E_SRC)/libs2eplugins)

stamps/libs2e-release-make: stamps/libs2e-release-configure  \
	$(call FIND_SOURCE,$(S2E_SRC)/libs2e) \
	$(call FIND_SOURCE,$(S2E_SRC)/libcpu) \
	$(call FIND_SOURCE,$(S2E_SRC)/libtcg) \
	$(call FIND_SOURCE,$(S2E_SRC)/libs2ecore) \
	$(call FIND_SOURCE,$(S2E_SRC)/libs2eplugins)

stamps/libs2e-release-install: stamps/libs2e-release-make
	mkdir -p $(S2E_PREFIX)/share/libs2e/

	install $(S2E_BUILD)/libs2e-release/x86_64-softmmu/libs2e.so $(S2E_PREFIX)/share/libs2e/libs2e-x86_64.so
	install $(S2E_BUILD)/libs2e-release/i386-softmmu/libs2e.so $(S2E_PREFIX)/share/libs2e/libs2e-i386.so

	install $(S2E_BUILD)/libs2e-release/x86_64-s2e-softmmu/op_helper.bc.x86_64 $(S2E_PREFIX)/share/libs2e/
	install $(S2E_BUILD)/libs2e-release/x86_64-s2e-softmmu/libs2e.so $(S2E_PREFIX)/share/libs2e/libs2e-x86_64-s2e.so

	install $(S2E_BUILD)/libs2e-release/i386-s2e-softmmu/op_helper.bc.i386  $(S2E_PREFIX)/share/libs2e/
	install $(S2E_BUILD)/libs2e-release/i386-s2e-softmmu/libs2e.so $(S2E_PREFIX)/share/libs2e/libs2e-i386-s2e.so

	install $(S2E_BUILD)/libs2e-release/x86_64-s2e_sp-softmmu/op_helper_sp.bc.x86_64 $(S2E_PREFIX)/share/libs2e/
	install $(S2E_BUILD)/libs2e-release/x86_64-s2e_sp-softmmu/libs2e.so $(S2E_PREFIX)/share/libs2e/libs2e-x86_64-s2e_sp.so

	install $(S2E_BUILD)/libs2e-release/i386-s2e_sp-softmmu/op_helper_sp.bc.i386  $(S2E_PREFIX)/share/libs2e/
	install $(S2E_BUILD)/libs2e-release/i386-s2e_sp-softmmu/libs2e.so $(S2E_PREFIX)/share/libs2e/libs2e-i386-s2e_sp.so

	install $(S2E_SRC)/libs2eplugins/src/s2e/Plugins/Support/KeyValueStore.py $(S2E_PREFIX)/bin/
	cd $(S2E_SRC) && if [ -f ".git/config" ]; then git rev-parse HEAD > $(S2E_PREFIX)/share/libs2e/git-sha1; fi

	touch $@

stamps/libs2e-debug-install: stamps/libs2e-debug-make
	mkdir -p $(S2E_PREFIX)/share/libs2e/

	install $(S2E_BUILD)/libs2e-debug/x86_64-softmmu/libs2e.so $(S2E_PREFIX)/share/libs2e/libs2e-x86_64.so

	install $(S2E_BUILD)/libs2e-debug/i386-softmmu/libs2e.so $(S2E_PREFIX)/share/libs2e/libs2e-i386.so

	install $(S2E_BUILD)/libs2e-debug/x86_64-s2e-softmmu/op_helper.bc.x86_64 $(S2E_PREFIX)/share/libs2e/
	install $(S2E_BUILD)/libs2e-debug/x86_64-s2e-softmmu/libs2e.so $(S2E_PREFIX)/share/libs2e/libs2e-x86_64-s2e.so

	install $(S2E_BUILD)/libs2e-debug/i386-s2e-softmmu/op_helper.bc.i386  $(S2E_PREFIX)/share/libs2e/
	install $(S2E_BUILD)/libs2e-debug/i386-s2e-softmmu/libs2e.so $(S2E_PREFIX)/share/libs2e/libs2e-i386-s2e.so

	install $(S2E_BUILD)/libs2e-debug/x86_64-s2e_sp-softmmu/op_helper_sp.bc.x86_64 $(S2E_PREFIX)/share/libs2e/
	install $(S2E_BUILD)/libs2e-debug/x86_64-s2e_sp-softmmu/libs2e.so $(S2E_PREFIX)/share/libs2e/libs2e-x86_64-s2e_sp.so

	install $(S2E_BUILD)/libs2e-debug/i386-s2e_sp-softmmu/op_helper_sp.bc.i386  $(S2E_PREFIX)/share/libs2e/
	install $(S2E_BUILD)/libs2e-debug/i386-s2e_sp-softmmu/libs2e.so $(S2E_PREFIX)/share/libs2e/libs2e-i386-s2e_sp.so

	install $(S2E_SRC)/libs2eplugins/src/s2e/Plugins/Support/KeyValueStore.py $(S2E_PREFIX)/bin/
	cd $(S2E_SRC) && if [ -f ".git/config" ]; then git rev-parse HEAD > $(S2E_PREFIX)/share/libs2e/git-sha1; fi

	touch $@

#########
# Tools #
#########

TOOLS_CONFIGURE_FLAGS = -DCMAKE_INSTALL_PREFIX=$(S2E_PREFIX)              \
                        -DCMAKE_C_COMPILER=$(CLANG_CC)                    \
                        -DCMAKE_CXX_COMPILER=$(CLANG_CXX)                 \
                        -DCMAKE_C_FLAGS="$(CFLAGS_ARCH)"                  \
                        -DCMAKE_PREFIX_PATH="$(S2E_PREFIX)"               \
                        -DLIBCPU_SRC_DIR=$(S2E_SRC)/libcpu                \
                        -DLIBTCG_SRC_DIR=$(S2E_SRC)/libtcg                \
                        -DS2EPLUGINS_SRC_DIR=$(S2E_SRC)/libs2eplugins/src \
                        -G "Unix Makefiles"

stamps/tools-debug-configure: stamps/llvm-debug-make stamps/libvmi-debug-make stamps/libfsigc++-debug-make stamps/libq-debug-make
stamps/tools-debug-configure: CONFIGURE_COMMAND = cmake $(TOOLS_CONFIGURE_FLAGS)                        \
                                                  -DLLVM_DIR=$(LLVM_BUILD)/llvm-debug/lib/cmake/llvm    \
                                                  -DVMI_DIR=$(S2E_BUILD)/libvmi-debug                   \
                                                  -DFSIGCXX_DIR=$(S2E_BUILD)/libfsigc++-debug           \
                                                  -DLIBQ_DIR=$(S2E_BUILD)/libq-debug                    \
                                                  -DCMAKE_BUILD_TYPE=Debug                              \
                                                  -DCMAKE_CXX_FLAGS="$(CXXFLAGS_DEBUG)"                 \
                                                  $(S2E_SRC)/tools

stamps/tools-release-configure: stamps/llvm-release-make stamps/libvmi-release-make stamps/libfsigc++-release-make stamps/libq-release-make
stamps/tools-release-configure: CONFIGURE_COMMAND = cmake $(TOOLS_CONFIGURE_FLAGS)                          \
                                                    -DLLVM_DIR=$(LLVM_BUILD)/llvm-release/lib/cmake/llvm    \
                                                    -DVMI_DIR=$(S2E_BUILD)/libvmi-release                   \
                                                    -DFSIGCXX_DIR=$(S2E_BUILD)/libfsigc++-release           \
                                                    -DLIBQ_DIR=$(S2E_BUILD)/libq-release                    \
                                                    -DCMAKE_BUILD_TYPE=$(RELEASE_BUILD_TYPE)                \
                                                    -DCMAKE_CXX_FLAGS="$(CXXFLAGS_RELEASE)"                 \
                                                    $(S2E_SRC)/tools

stamps/tools-debug-make: stamps/tools-debug-configure

stamps/tools-release-make: stamps/tools-release-configure

stamps/tools-release-install: stamps/tools-release-make
	$(MAKE) -C tools-release install
	touch $@

stamps/tools-debug-install: stamps/tools-debug-make
	$(MAKE) -C tools-debug install
	touch $@

###############
# Guest tools #
###############

stamps/guest-tools32-configure: CONFIGURE_COMMAND = cmake                                                                    \
                                                    -DCMAKE_C_COMPILER=$(CLANG_CC)                                           \
                                                    -DCMAKE_INSTALL_PREFIX=$(S2E_PREFIX)/bin/guest-tools32                   \
                                                    -DCMAKE_TOOLCHAIN_FILE=$(S2E_SRC)/guest/cmake/Toolchain-linux-i686.cmake \
                                                    $(S2E_SRC)/guest

stamps/guest-tools64-configure: CONFIGURE_COMMAND = cmake                                                                       \
                                                    -DCMAKE_C_COMPILER=$(CLANG_CC)                                              \
                                                    -DCMAKE_INSTALL_PREFIX=$(S2E_PREFIX)/bin/guest-tools64                      \
                                                    -DCMAKE_TOOLCHAIN_FILE=$(S2E_SRC)/guest/cmake/Toolchain-linux-x86_64.cmake  \
                                                    $(S2E_SRC)/guest

stamps/guest-tools32-win-configure: CONFIGURE_COMMAND = cmake                                                                       \
                                                        -DCMAKE_INSTALL_PREFIX=$(S2E_PREFIX)/bin/guest-tools32                      \
                                                        -DCMAKE_TOOLCHAIN_FILE=$(S2E_SRC)/guest/cmake/Toolchain-windows-i686.cmake  \
                                                        $(S2E_SRC)/guest

stamps/guest-tools64-win-configure: CONFIGURE_COMMAND = cmake                                                                        \
                                                        -DCMAKE_INSTALL_PREFIX=$(S2E_PREFIX)/bin/guest-tools64                       \
                                                        -DCMAKE_TOOLCHAIN_FILE=$(S2E_SRC)/guest/cmake/Toolchain-windows-x86_64.cmake \
                                                        $(S2E_SRC)/guest

stamps/guest-tools32-make: stamps/guest-tools32-configure

stamps/guest-tools64-make: stamps/guest-tools64-configure

stamps/guest-tools32-win-make: stamps/guest-tools32-win-configure

stamps/guest-tools64-win-make: stamps/guest-tools64-win-configure

# Install precompiled windows drivers
$(S2E_PREFIX)/bin/guest-tools32 $(S2E_PREFIX)/bin/guest-tools64:
	mkdir -p "$@"

define DOWNLOAD_S2E_TOOL
  $(S2E_PREFIX)/bin/guest-tools$1/$2: | $(S2E_PREFIX)/bin/guest-tools$1
	$(call DOWNLOAD,$(GUEST_TOOLS_BINARIES_URL)/$3,$$@)
endef

$(eval $(call DOWNLOAD_S2E_TOOL,32,s2e.sys,s2e32.sys))
$(eval $(call DOWNLOAD_S2E_TOOL,32,s2e.inf,s2e.inf))
$(eval $(call DOWNLOAD_S2E_TOOL,32,drvctl.exe,drvctl32.exe))
$(eval $(call DOWNLOAD_S2E_TOOL,32,libs2e32.dll,libs2e32.dll))
$(eval $(call DOWNLOAD_S2E_TOOL,32,tickler.exe,tickler32.exe))

$(eval $(call DOWNLOAD_S2E_TOOL,64,s2e.sys,s2e.sys))
$(eval $(call DOWNLOAD_S2E_TOOL,64,s2e.inf,s2e.inf))
$(eval $(call DOWNLOAD_S2E_TOOL,64,drvctl.exe,drvctl.exe))
$(eval $(call DOWNLOAD_S2E_TOOL,64,libs2e32.dll,libs2e32.dll))
$(eval $(call DOWNLOAD_S2E_TOOL,64,libs2e64.dll,libs2e64.dll))
$(eval $(call DOWNLOAD_S2E_TOOL,64,tickler.exe,tickler64.exe))

guest-tools32-windrv: $(addprefix $(S2E_PREFIX)/bin/guest-tools32/,s2e.sys s2e.inf drvctl.exe libs2e32.dll tickler.exe)
	echo $^

guest-tools64-windrv: $(addprefix $(S2E_PREFIX)/bin/guest-tools64/,s2e.sys s2e.inf drvctl.exe libs2e32.dll libs2e64.dll tickler.exe)
	echo $^

stamps/guest-tools%-win-install: stamps/guest-tools%-win-make guest-tools32-windrv guest-tools64-windrv
	$(MAKE) -C guest-tools$*-win install

stamps/guest-tools%-install: stamps/guest-tools%-make guest-tools32-windrv guest-tools64-windrv
	$(MAKE) -C guest-tools$* install
