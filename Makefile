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

# Check the build directory
ifeq ($(shell ls libs2e/src/libs2e.c 2>&1),libs2e/src/libs2e.c)
    $(error You should not run make in the S2E source directory!)
endif

#############
# Variables #
#############

# S2E variables
BUILD_SCRIPTS_SRC?=$(dir $(realpath $(lastword $(MAKEFILE_LIST))))
S2E_SRC?=$(realpath $(BUILD_SCRIPTS_SRC)/../)
S2E_PREFIX?=$(CURDIR)/opt
S2E_BUILD:=$(CURDIR)

# Either choose Release or RelWithDebInfo
RELEASE_BUILD_TYPE=RelWithDebInfo

# corei7 avoids instructions not supported by VirtualBox. Use "native" instead
# to optimize for your current CPU.
BUILD_ARCH?=x86-64

# Set the number of parallel build jobs
OS:=$(shell uname)
ifeq ($(PARALLEL), no)
JOBS:=1
else ifeq ($(OS),Darwin)
JOBS:=$(patsubst hw.ncpu:%,%,$(shell sysctl hw.ncpu))
else ifeq ($(OS),Linux)
JOBS:=$(shell grep -c ^processor /proc/cpuinfo)
endif

MAKE:=make -j$(JOBS)

CFLAGS_ARCH:=-march=$(BUILD_ARCH) -mno-sse4.1
CXXFLAGS_ARCH:=-march=$(BUILD_ARCH) -mno-sse4.1

# TODO: figure out how to automatically get the latest version without
# having to update this URL.
GUEST_TOOLS_BINARIES_URL=https://github.com/S2E/guest-tools/releases/download/v2.0.0/

# LLVM variables
LLVM_BUILD?=$(S2E_BUILD)
ifeq ($(LLVM_BUILD),$(S2E_BUILD))
LLVM_DIRS=llvm-release llvm-debug
endif

LLVM_VERSION=3.9.1
LLVM_SRC=llvm-$(LLVM_VERSION).src.tar.xz
LLVM_SRC_DIR=llvm-$(LLVM_VERSION).src
LLVM_SRC_URL = http://llvm.org/releases/$(LLVM_VERSION)

# The Python script should only return a single word - the suffix of the Clang
# binary to download. If an error message is printed to stderr, the Makefile
# error will be triggered.
CLANG_BINARY_SUFFIX=$(shell python $(BUILD_SCRIPTS_SRC)/determine_clang_binary_suffix.py 2>&1)
ifneq ($(words $(CLANG_BINARY_SUFFIX)), 1)
$(error "Failed to determine Clang binary to download: $(CLANG_BINARY_SUFFIX)")
endif

CLANG_BINARY_DIR=clang+llvm-$(LLVM_VERSION)-$(CLANG_BINARY_SUFFIX)
CLANG_BINARY=$(CLANG_BINARY_DIR).tar.xz

CLANG_SRC=cfe-$(LLVM_VERSION).src.tar.xz
CLANG_SRC_DIR=cfe-$(LLVM_VERSION).src
CLANG_DEST_DIR=$(LLVM_SRC_DIR)/tools/clang

COMPILER_RT_SRC=compiler-rt-$(LLVM_VERSION).src.tar.xz
COMPILER_RT_SRC_DIR=compiler-rt-$(LLVM_VERSION).src
COMPILER_RT_DEST_DIR=$(LLVM_SRC_DIR)/projects/compiler-rt

# Capstone variables
CAPSTONE_VERSION=3.0.5
CAPSTONE_SRC=$(CAPSTONE_VERSION).tar.gz
CAPSTONE_BUILD_DIR=capstone-$(CAPSTONE_VERSION)-build
CAPSTONE_SRC_DIR=capstone-$(CAPSTONE_VERSION)
CAPSTONE_URL=https://github.com/aquynh/capstone/archive/$(CAPSTONE_SRC)

# Z3 variables
Z3_VERSION=4.7.1
Z3_SRC=z3-$(Z3_VERSION).tar.gz
Z3_SRC_DIR=z3-z3-$(Z3_VERSION)
Z3_BUILD_DIR=z3
Z3_URL=https://github.com/Z3Prover/z3

# Lua variables
LUA_VERSION=5.3.4
LUA_SRC=lua-$(LUA_VERSION).tar.gz
LUA_DIR=lua-$(LUA_VERSION)

# SOCI variables
SOCI_SRC_DIR=soci-src
SOCI_BUILD_DIR=soci
SOCI_GIT_REV=f0c0d25a9160a237c9ef8eddf9f28651621192f3
SOCI_GIT_URL=https://github.com/SOCI/soci.git

# Google Test
GTEST_VERSION=1.8.0
GTEST_SRC_DIR=$(S2E_BUILD)/googletest-release-$(GTEST_VERSION)
GTEST_URL=https://github.com/google/googletest/archive/release-$(GTEST_VERSION).tar.gz

KLEE_QEMU_DIRS=$(foreach suffix,-debug -release,$(addsuffix $(suffix),klee qemu))

###########
# Targets #
###########

all: all-release guest-tools

all-release: stamps/qemu-release-make stamps/libs2e-release-make stamps/tools-release-make stamps/decree-make
all-debug: stamps/qemu-debug-make stamps/libs2e-debug-make stamps/tools-debug-make stamps/decree-make

guest-tools: stamps/guest-tools32-make stamps/guest-tools64-make
guest-tools-win: stamps/guest-tools32-win-make stamps/guest-tools64-win-make

guest-tools-install: stamps/guest-tools32-install stamps/guest-tools64-install
guest-tools-win-install: stamps/guest-tools32-win-install stamps/guest-tools64-win-install

install: all-release stamps/libs2e-release-install stamps/tools-release-install \
    stamps/libvmi-release-install stamps/decree-install guest-tools-install     \
    guest-tools-win-install stamps/llvm-release-install
install-debug: all-debug stamps/libs2e-debug-install stamps/tools-debug-install \
    stamps/libvmi-debug-install stamps/decree-install guest-tools-install       \
    guest-tools-win-install stamps/llvm-release-install

# From https://stackoverflow.com/questions/4219255/how-do-you-get-the-list-of-targets-in-a-makefile
list:
	@$(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null |                                  \
		awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' | \
		sort | egrep -v -e '^[^[:alnum:]]' -e '^$@$$' | xargs

.PHONY: all all-debug all-release
.PHONY: clean distclean guestclean
.PHONY: list

ALWAYS:

$(KLEE_QEMU_DIRS) $(LLVM_DIRS) libq-debug libq-release              \
libfsigc++-debug libfsigc++-release libvmi-debug libvmi-release     \
libcoroutine-release libcoroutine-debug libs2e-debug libs2e-release \
tools-debug tools-release                                           \
guest-tools32 guest-tools64 guest-tools32-win guest-tools64-win     \
decree stamps:
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

ifeq ($(LLVM_BUILD),$(S2E_BUILD))
# Download LLVM
$(LLVM_SRC) $(CLANG_SRC) $(COMPILER_RT_SRC) $(CLANG_BINARY):
	wget $(LLVM_SRC_URL)/$@

.INTERMEDIATE: $(CLANG_SRC_DIR) $(COMPILER_RT_SRC_DIR) $(CLANG_BINARY_DIR)

$(LLVM_SRC_DIR): $(LLVM_SRC) $(CLANG_SRC_DIR) $(COMPILER_RT_SRC_DIR)
	tar -xmf $<
	mv $(CLANG_SRC_DIR) $(CLANG_DEST_DIR)
	mv $(COMPILER_RT_SRC_DIR) $(COMPILER_RT_DEST_DIR)

$(CLANG_SRC_DIR): $(CLANG_SRC)
	tar -xmf $<

$(COMPILER_RT_SRC_DIR): $(COMPILER_RT_SRC)
	tar -xmf $<

else
# Use the specified LLVM build folder, don't build LLVM
endif

# Download Lua
$(LUA_SRC):
	wget http://www.lua.org/ftp/$(LUA_SRC)

$(LUA_DIR): | $(LUA_SRC)
	tar -zxf $(LUA_SRC)
	cp $(S2E_SRC)/lua/luaconf.h $(LUA_DIR)/src

# Download Z3
$(Z3_BUILD_DIR):
	wget $(Z3_URL)/archive/$(Z3_SRC)
	tar -zxf $(Z3_SRC)
	mkdir -p $(S2E_BUILD)/$(Z3_BUILD_DIR)

# Download SOCI
$(SOCI_BUILD_DIR):
	git clone $(SOCI_GIT_URL) $(SOCI_SRC_DIR)
	cd $(SOCI_SRC_DIR) && git checkout $(SOCI_GIT_REV)
	mkdir -p $(S2E_BUILD)/$(SOCI_BUILD_DIR)

# Download GTest
$(GTEST_SRC_DIR):
	cd $(S2E_BUILD) && wget -O $(GTEST_SRC_DIR).tar.gz $(GTEST_URL)
	cd $(S2E_BUILD) && tar xzvf $(GTEST_SRC_DIR).tar.gz

# Download Capstone
$(CAPSTONE_BUILD_DIR):
	wget -O $(CAPSTONE_SRC_DIR).tar.gz $(CAPSTONE_URL)
	tar -zxf $(CAPSTONE_SRC_DIR).tar.gz
	mkdir -p $(S2E_BUILD)/$(CAPSTONE_BUILD_DIR)

ifeq ($(LLVM_BUILD),$(S2E_BUILD))


########
# LLVM #
########

stamps/clang-binary: $(CLANG_BINARY) | stamps
	tar -xmf $<
	mkdir -p $(S2E_PREFIX)
	cp -r $(CLANG_BINARY_DIR)/* $(S2E_PREFIX)
	rm -r $(CLANG_BINARY_DIR)/*
	touch $@

CLANG_CC = $(S2E_PREFIX)/bin/clang
CLANG_CXX = $(S2E_PREFIX)/bin/clang++
CLANG_LIB = $(S2E_PREFIX)/lib

LLVM_CONFIGURE_FLAGS = -DLLVM_TARGETS_TO_BUILD="X86"        \
                       -DLLVM_TARGET_ARCH="X86_64"          \
                       -DLLVM_INCLUDE_EXAMPLES=Off          \
                       -DLLVM_INCLUDE_DOCS=Off              \
                       -DLLVM_INCLUDE_TESTS=Off             \
                       -DLLVM_ENABLE_RTTI=On                \
                       -DLLVM_ENABLE_EH=On                  \
                       -DLLVM_BINUTILS_INCDIR=/usr/include  \
                       -DCOMPILER_RT_BUILD_SANITIZERS=Off   \
                       -DENABLE_ASSERTIONS=On               \
                       -DCMAKE_C_COMPILER=$(CLANG_CC)       \
                       -DCMAKE_CXX_COMPILER=$(CLANG_CXX)    \
                       -DCMAKE_C_FLAGS=$(CFLAGS_ARCH)       \
                       -DCMAKE_CXX_FLAGS=$(CXXFLAGS_ARCH)   \
                       -G "Unix Makefiles"

stamps/llvm-debug-configure: stamps/clang-binary $(LLVM_SRC_DIR)
stamps/llvm-debug-configure: CONFIGURE_COMMAND = cmake $(LLVM_CONFIGURE_FLAGS)  \
                                                 -DCMAKE_BUILD_TYPE=Debug       \
                                                 $(LLVM_BUILD)/$(LLVM_SRC_DIR)

stamps/llvm-release-configure: stamps/clang-binary $(LLVM_SRC_DIR)
stamps/llvm-release-configure: CONFIGURE_COMMAND = cmake $(LLVM_CONFIGURE_FLAGS)\
                                                   -DCMAKE_BUILD_TYPE=Release   \
                                                   $(LLVM_BUILD)/$(LLVM_SRC_DIR)

stamps/llvm-debug-make: stamps/llvm-debug-configure

stamps/llvm-release-make: stamps/llvm-release-configure

stamps/llvm-release-install: stamps/llvm-release-make
	cp $(S2E_BUILD)/llvm-release/lib/LLVMgold.so $(S2E_PREFIX)/lib

else
stamps/llvm-release-make:
	echo "Won't build"
stamps/llvm-debug-make:
	echo "Won't build"
stamps/llvm-release-install:
	echo "Won't build"
endif

########
# SOCI #
########

SOCI_CONFIGURE_FLAGS = -DCMAKE_INSTALL_PREFIX=$(S2E_PREFIX) \
                       -DCMAKE_C_COMPILER=$(CLANG_CC)       \
                       -DCMAKE_CXX_COMPILER=$(CLANG_CXX)    \
                       -DCMAKE_C_FLAGS="-fPIC"              \
                       -G "Unix Makefiles"

stamps/soci-configure: stamps/clang-binary $(SOCI_BUILD_DIR)
stamps/soci-configure: CONFIGURE_COMMAND = cmake $(SOCI_CONFIGURE_FLAGS)    \
                                           $(S2E_BUILD)/$(SOCI_SRC_DIR)/src

stamps/soci-make: stamps/soci-configure
	$(MAKE) -C $(SOCI_BUILD_DIR)
	$(MAKE) -C $(SOCI_BUILD_DIR) install
	touch $@

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

stamps/z3-configure: stamps/clang-binary $(Z3_BUILD_DIR)
	cd $(Z3_SRC_DIR) &&                                         \
	python contrib/cmake/bootstrap.py create
	cd $(Z3_BUILD_DIR) &&                                       \
	cmake $(Z3_CONFIGURE_FLAGS) $(S2E_BUILD)/$(Z3_SRC_DIR)
	touch $@

stamps/z3-make: stamps/z3-configure
	$(MAKE) -C $(Z3_BUILD_DIR)
	$(MAKE) -C $(Z3_BUILD_DIR) install
	touch $@

############
# Capstone #
############

CAPSTONE_CONFIGURE_FLAGS = -DCMAKE_INSTALL_PREFIX=$(S2E_PREFIX)         \
                     -DCMAKE_C_COMPILER=$(CLANG_CC)                     \
                     -DCMAKE_CXX_COMPILER=$(CLANG_CXX)                  \
                     -DCMAKE_C_FLAGS="-fno-omit-frame-pointer -fPIC"    \
                     -DCMAKE_CXX_FLAGS="-fno-omit-frame-pointer -fPIC"  \
                     -G "Unix Makefiles"

stamps/capstone-configure: stamps/clang-binary $(CAPSTONE_BUILD_DIR)
	cd $(CAPSTONE_BUILD_DIR) &&                                         \
	cmake $(CAPSTONE_CONFIGURE_FLAGS) $(S2E_BUILD)/$(CAPSTONE_SRC_DIR)
	touch $@

stamps/capstone-make: stamps/capstone-configure
	$(MAKE) -C $(CAPSTONE_BUILD_DIR)
	$(MAKE) -C $(CAPSTONE_BUILD_DIR) install
	touch $@

#######
# Lua #
#######

stamps/lua-make: $(LUA_DIR)
	sed -i 's/-lreadline//g' $(LUA_DIR)/src/Makefile
	$(MAKE) -C $^ linux CFLAGS="-DLUA_USE_LINUX -O2 -g -fPIC"
	touch $@

########
# KLEE #
########

KLEE_CONFIGURE_FLAGS = -DCMAKE_INSTALL_PREFIX=$(S2E_PREFIX)                                 \
                       -DCMAKE_C_FLAGS="$(CFLAGS_ARCH) -fno-omit-frame-pointer -fPIC"       \
                       -DCMAKE_CXX_FLAGS="$(CXXFLAGS_ARCH) -fno-omit-frame-pointer -fPIC"   \
                       -DCMAKE_C_COMPILER=$(CLANG_CC)                                       \
                       -DCMAKE_CXX_COMPILER=$(CLANG_CXX)                                    \
                       -DUSE_CMAKE_FIND_PACKAGE_LLVM=On                                     \
                       -DENABLE_UNIT_TESTS=On                                               \
                       -DGTEST_SRC_DIR=$(S2E_BUILD)/googletest-release-1.8.0                \
                       -DENABLE_DOCS=Off                                                    \
                       -DENABLE_SOLVER_Z3=On                                                \
                       -DZ3_INCLUDE_DIRS=$(S2E_PREFIX)/include                              \
                       -DZ3_LIBRARIES=$(S2E_PREFIX)/lib/libz3.a

stamps/klee-debug-configure: stamps/llvm-debug-make stamps/z3-make | $(GTEST_SRC_DIR)
stamps/klee-debug-configure: CONFIGURE_COMMAND = cmake $(KLEE_CONFIGURE_FLAGS)                      \
                                                 -DCMAKE_BUILD_TYPE=Debug                           \
                                                 -DLLVM_DIR=$(LLVM_BUILD)/llvm-debug/lib/cmake/llvm \
                                                 $(S2E_SRC)/klee

stamps/klee-release-configure: stamps/llvm-release-make stamps/z3-make | $(GTEST_SRC_DIR)
stamps/klee-release-configure: CONFIGURE_COMMAND = cmake $(KLEE_CONFIGURE_FLAGS)                        \
                                                   -DCMAKE_BUILD_TYPE=$(RELEASE_BUILD_TYPE)             \
                                                   -DLLVM_DIR=$(LLVM_BUILD)/llvm-release/lib/cmake/llvm \
                                                   $(S2E_SRC)/klee

stamps/klee-debug-make: stamps/klee-debug-configure

stamps/klee-release-make: stamps/klee-release-configure

##########
# LibVMI #
##########

LIBVMI_COMMON_FLAGS = -DCMAKE_INSTALL_PREFIX=$(S2E_PREFIX)          \
                      -DCMAKE_MODULE_PATH=$(S2E_SRC)/cmake          \
                      -DCMAKE_C_COMPILER=$(CLANG_CC)                \
                      -DCMAKE_CXX_COMPILER=$(CLANG_CXX)             \
                      -DCMAKE_C_FLAGS="$(CFLAGS_ARCH) -fPIC"        \
                      -DCMAKE_CXX_FLAGS="$(CXXFLAGS_ARCH) -fPIC"    \
                      -G "Unix Makefiles"

stamps/libvmi-debug-configure: stamps/llvm-debug-make
stamps/libvmi-debug-configure: CONFIGURE_COMMAND = cmake $(LIBVMI_COMMON_FLAGS)                         \
                                                   -DLLVM_DIR=$(LLVM_BUILD)/llvm-debug/lib/cmake/llvm   \
                                                   -DCMAKE_BUILD_TYPE=Debug                             \
                                                   $(S2E_SRC)/libvmi

stamps/libvmi-release-configure: stamps/llvm-release-make
stamps/libvmi-release-configure: CONFIGURE_COMMAND = cmake $(LIBVMI_COMMON_FLAGS)                           \
                                                     -DLLVM_DIR=$(LLVM_BUILD)/llvm-release/lib/cmake/llvm   \
                                                     -DCMAKE_BUILD_TYPE=$(RELEASE_BUILD_TYPE)               \
                                                     $(S2E_SRC)/libvmi

stamps/libvmi-debug-make: stamps/libvmi-debug-configure

stamps/libvmi-release-make: stamps/libvmi-release-configure

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
                          -DCMAKE_CXX_FLAGS="$(CXXFLAGS_ARCH)"  \
                          -G "Unix Makefiles"

stamps/libfsigc++-debug-configure: stamps/clang-binary

stamps/libfsigc++-debug-configure: CONFIGURE_COMMAND = cmake $(LIBFSIGCXX_COMMON_FLAGS) \
                                                       -DCMAKE_BUILD_TYPE=Debug         \
                                                       $(S2E_SRC)/libfsigc++


stamps/libfsigc++-release-configure: stamps/clang-binary

stamps/libfsigc++-release-configure: CONFIGURE_COMMAND = cmake $(LIBFSIGCXX_COMMON_FLAGS)   \
                                     -DCMAKE_BUILD_TYPE=$(RELEASE_BUILD_TYPE)               \
                                     $(S2E_SRC)/libfsigc++

stamps/libfsigc++-debug-make: stamps/libfsigc++-debug-configure

stamps/libfsigc++-release-make: stamps/libfsigc++-release-configure

########
# libq #
########

LIBQ_COMMON_FLAGS = -DCMAKE_MODULE_PATH=$(S2E_SRC)/cmake    \
                    -DCMAKE_C_COMPILER=$(CLANG_CC)          \
                    -DCMAKE_CXX_COMPILER=$(CLANG_CXX)       \
                    -DCMAKE_C_FLAGS="$(CFLAGS_ARCH)"        \
                    -DCMAKE_CXX_FLAGS="$(CXXFLAGS_ARCH)"    \
                    -G "Unix Makefiles"

stamps/libq-debug-configure: stamps/clang-binary

stamps/libq-debug-configure: CONFIGURE_COMMAND = cmake $(LIBQ_COMMON_FLAGS) \
                                                 -DCMAKE_BUILD_TYPE=Debug   \
                                                 $(S2E_SRC)/libq


stamps/libq-release-configure: stamps/clang-binary

stamps/libq-release-configure: CONFIGURE_COMMAND = cmake $(LIBQ_COMMON_FLAGS)                 \
                                                   -DCMAKE_BUILD_TYPE=$(RELEASE_BUILD_TYPE)   \
                                                   $(S2E_SRC)/libq

stamps/libq-debug-make: stamps/libq-debug-configure

stamps/libq-release-make: stamps/libq-release-configure

################
# libcoroutine #
################

LIBCOROUTINE_COMMON_FLAGS = -DCMAKE_MODULE_PATH=$(S2E_SRC)/cmake    \
                            -DCMAKE_C_COMPILER=$(CLANG_CC)          \
                            -DCMAKE_CXX_COMPILER=$(CLANG_CXX)       \
                            -DCMAKE_C_FLAGS="$(CFLAGS_ARCH)"        \
                            -DCMAKE_CXX_FLAGS="$(CXXFLAGS_ARCH)"    \
                            -G "Unix Makefiles"

stamps/libcoroutine-debug-configure: stamps/clang-binary

stamps/libcoroutine-debug-configure: CONFIGURE_COMMAND = cmake $(LIBCOROUTINE_COMMON_FLAGS) \
                                                         -DCMAKE_BUILD_TYPE=Debug           \
                                                         $(S2E_SRC)/libcoroutine


stamps/libcoroutine-release-configure: stamps/clang-binary

stamps/libcoroutine-release-configure: CONFIGURE_COMMAND = cmake $(LIBCOROUTINE_COMMON_FLAGS)        \
                                                           -DCMAKE_BUILD_TYPE=$(RELEASE_BUILD_TYPE)  \
                                                           $(S2E_SRC)/libcoroutine

stamps/libcoroutine-debug-make: stamps/libcoroutine-debug-configure

stamps/libcoroutine-release-make: stamps/libcoroutine-release-configure

########
# QEMU #
########

QEMU_TARGETS=i386-softmmu,x86_64-softmmu

QEMU_CONFIGURE_FLAGS = --prefix=$(S2E_PREFIX)        \
                       --target-list=$(QEMU_TARGETS) \
                       --disable-smartcard           \
                       --disable-virtfs              \
                       --disable-xen                 \
                       --disable-bluez               \
                       --disable-vde                 \
                       --disable-libiscsi            \
                       --disable-docs                \
                       --disable-spice               \
                       $(EXTRA_QEMU_FLAGS)

QEMU_DEBUG_FLAGS = --enable-debug

QEMU_RELEASE_FLAGS =

stamps/qemu-debug-configure: export CFLAGS:=$(CFLAGS_ARCH) -fno-omit-frame-pointer
stamps/qemu-debug-configure: export CXXFLAGS:=$(CXXFLAGS_ARCH) -fno-omit-frame-pointer
stamps/qemu-debug-configure: CONFIGURE_COMMAND = $(S2E_SRC)/qemu/configure  \
                                                 $(QEMU_CONFIGURE_FLAGS)    \
                                                 $(QEMU_DEBUG_FLAGS)

stamps/qemu-release-configure: CONFIGURE_COMMAND = $(S2E_SRC)/qemu/configure    \
                                                   $(QEMU_CONFIGURE_FLAGS)      \
                                                   $(QEMU_RELEASE_FLAGS)

stamps/qemu-debug-make: stamps/qemu-debug-configure
	$(MAKE) -C qemu-debug $(BUILD_OPTS) install
	touch $@

stamps/qemu-release-make: stamps/qemu-release-configure
	$(MAKE) -C qemu-release $(BUILD_OPTS) install
	touch $@


##########
# libs2e #
##########

LIBS2E_CONFIGURE_FLAGS = --with-cc=$(CLANG_CC)                                      \
                         --with-cxx=$(CLANG_CXX)                                    \
                         --with-cflags=$(CFLAGS_ARCH)                               \
                         --with-cxxflags=$(CXXFLAGS_ARCH)                           \
                         --with-liblua=$(S2E_BUILD)/$(LUA_DIR)/src                  \
                         --with-s2e-guest-incdir=$(S2E_SRC)/guest/common/include    \
                         --with-z3-incdir=$(S2E_PREFIX)/include                     \
                         --with-z3-libdir=$(S2E_PREFIX)/lib                         \
                         --with-capstone-incdir=$(S2E_PREFIX)/include               \
                         --with-capstone-libdir=$(S2E_PREFIX)/lib                   \
                         --with-libtcg-src=$(S2E_SRC)/libtcg                        \
                         --with-libcpu-src=$(S2E_SRC)/libcpu                        \
                         --with-libs2ecore-src=$(S2E_SRC)/libs2ecore                \
                         --with-libs2eplugins-src=$(S2E_SRC)/libs2eplugins          \
                         $(EXTRA_QEMU_FLAGS)

LIBS2E_DEBUG_FLAGS = --with-llvm=$(LLVM_BUILD)/llvm-debug                           \
                     --with-klee=$(S2E_BUILD)/klee-debug                            \
                     --with-libvmi=$(S2E_BUILD)/libvmi-debug                        \
                     --with-fsigc++=$(S2E_BUILD)/libfsigc++-debug                   \
                     --with-libq=$(S2E_BUILD)/libq-debug                            \
                     --with-libcoroutine=$(S2E_BUILD)/libcoroutine-debug            \
                     --enable-debug

LIBS2E_RELEASE_FLAGS = --with-llvm=$(LLVM_BUILD)/llvm-release                       \
                       --with-klee=$(S2E_BUILD)/klee-release                        \
                       --with-libvmi=$(S2E_BUILD)/libvmi-release                    \
                       --with-fsigc++=$(S2E_BUILD)/libfsigc++-release               \
                       --with-libq=$(S2E_BUILD)/libq-release                        \
                       --with-libcoroutine=$(S2E_BUILD)/libcoroutine-release

stamps/libs2e-debug-configure: $(S2E_SRC)/libs2e/configure
stamps/libs2e-debug-configure: stamps/lua-make stamps/libvmi-debug-make         \
    stamps/klee-debug-make stamps/soci-make stamps/libfsigc++-debug-make        \
    stamps/libq-debug-make stamps/libcoroutine-debug-make stamps/capstone-make
stamps/libs2e-debug-configure: CONFIGURE_COMMAND = $(S2E_SRC)/libs2e/configure  \
                                                   $(LIBS2E_CONFIGURE_FLAGS)    \
                                                   $(LIBS2E_DEBUG_FLAGS)

stamps/libs2e-release-configure: $(S2E_SRC)/libs2e/configure
stamps/libs2e-release-configure: stamps/lua-make stamps/libvmi-release-make     \
    stamps/klee-release-make stamps/soci-make stamps/libfsigc++-release-make    \
    stamps/libq-release-make stamps/libcoroutine-release-make  stamps/capstone-make
stamps/libs2e-release-configure: CONFIGURE_COMMAND = $(S2E_SRC)/libs2e/configure    \
                                                     $(LIBS2E_CONFIGURE_FLAGS)      \
                                                     $(LIBS2E_RELEASE_FLAGS)

stamps/libs2e-debug-make: stamps/libs2e-debug-configure

stamps/libs2e-release-make: stamps/libs2e-release-configure

# Don't install old S2E anymore, it will be gone soon.
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
	cd $(S2E_SRC) && if [ -d ".git" ]; then git rev-parse HEAD > $(S2E_PREFIX)/share/libs2e/git-sha1; fi

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
	cd $(S2E_SRC) && if [ -d ".git" ]; then git rev-parse HEAD > $(S2E_PREFIX)/share/libs2e/git-sha1; fi

	touch $@

#########
# Tools #
#########

TOOLS_CONFIGURE_FLAGS = -DCMAKE_INSTALL_PREFIX=$(S2E_PREFIX)              \
                        -DCMAKE_C_COMPILER=$(CLANG_CC)                    \
                        -DCMAKE_CXX_COMPILER=$(CLANG_CXX)                 \
                        -DCMAKE_C_FLAGS=$(CFLAGS_ARCH)                    \
                        -DCMAKE_CXX_FLAGS=$(CXXFLAGS_ARCH)                \
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
                                                  $(S2E_SRC)/tools

stamps/tools-release-configure: stamps/llvm-release-make stamps/libvmi-release-make stamps/libfsigc++-release-make stamps/libq-release-make
stamps/tools-release-configure: CONFIGURE_COMMAND = cmake $(TOOLS_CONFIGURE_FLAGS)                          \
                                                    -DLLVM_DIR=$(LLVM_BUILD)/llvm-release/lib/cmake/llvm    \
                                                    -DVMI_DIR=$(S2E_BUILD)/libvmi-release                   \
                                                    -DFSIGCXX_DIR=$(S2E_BUILD)/libfsigc++-release           \
                                                    -DLIBQ_DIR=$(S2E_BUILD)/libq-release                    \
                                                    -DCMAKE_BUILD_TYPE=$(RELEASE_BUILD_TYPE)                \
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

stamps/guest-tools32-configure: CONFIGURE_COMMAND = cmake                                                                   \
                                                    -DCMAKE_C_COMPILER=$(CLANG_CC)                                          \
                                                    -DCMAKE_INSTALL_PREFIX=$(S2E_PREFIX)/bin/guest-tools32                   \
                                                    -DCMAKE_TOOLCHAIN_FILE=$(S2E_SRC)/guest/cmake/Toolchain-linux-i686.cmake \
                                                    $(S2E_SRC)/guest

stamps/guest-tools64-configure: CONFIGURE_COMMAND = cmake                                                                       \
                                                    -DCMAKE_C_COMPILER=$(CLANG_CC)                                              \
                                                    -DCMAKE_INSTALL_PREFIX=$(S2E_PREFIX)/bin/guest-tools64                       \
                                                    -DCMAKE_TOOLCHAIN_FILE=$(S2E_SRC)/guest/cmake/Toolchain-linux-x86_64.cmake   \
                                                    $(S2E_SRC)/guest

stamps/guest-tools32-win-configure: CONFIGURE_COMMAND = cmake                                                                       \
                                                        -DCMAKE_INSTALL_PREFIX=$(S2E_PREFIX)/bin/guest-tools32                       \
                                                        -DCMAKE_TOOLCHAIN_FILE=$(S2E_SRC)/guest/cmake/Toolchain-windows-i686.cmake   \
                                                        $(S2E_SRC)/guest

stamps/guest-tools64-win-configure: CONFIGURE_COMMAND = cmake                                                                       \
                                                        -DCMAKE_INSTALL_PREFIX=$(S2E_PREFIX)/bin/guest-tools64                       \
                                                        -DCMAKE_TOOLCHAIN_FILE=$(S2E_SRC)/guest/cmake/Toolchain-windows-x86_64.cmake \
                                                        $(S2E_SRC)/guest

stamps/guest-tools32-make: stamps/guest-tools32-configure

stamps/guest-tools64-make: stamps/guest-tools64-configure

stamps/guest-tools32-win-make: stamps/guest-tools32-win-configure

stamps/guest-tools64-win-make: stamps/guest-tools64-win-configure

# Install precompiled windows drivers
guest-tools32-windrv:
	mkdir -p $(S2E_PREFIX)/bin/guest-tools32
	cd $(S2E_PREFIX)/bin/guest-tools32 && wget -O s2e.sys $(GUEST_TOOLS_BINARIES_URL)/s2e32.sys
	cd $(S2E_PREFIX)/bin/guest-tools32 && wget -O s2e.inf $(GUEST_TOOLS_BINARIES_URL)/s2e.inf
	cd $(S2E_PREFIX)/bin/guest-tools32 && wget -O drvctl.exe $(GUEST_TOOLS_BINARIES_URL)/drvctl32.exe

guest-tools64-windrv:
	mkdir -p $(S2E_PREFIX)/bin/guest-tools64
	cd $(S2E_PREFIX)/bin/guest-tools64 && wget -O s2e.sys $(GUEST_TOOLS_BINARIES_URL)/s2e.sys
	cd $(S2E_PREFIX)/bin/guest-tools64 && wget -O s2e.inf $(GUEST_TOOLS_BINARIES_URL)/s2e.inf
	cd $(S2E_PREFIX)/bin/guest-tools64 && wget -O drvctl.exe $(GUEST_TOOLS_BINARIES_URL)/drvctl.exe

stamps/guest-tools%-win-install: stamps/guest-tools%-win-make guest-tools32-windrv guest-tools64-windrv
	$(MAKE) -C guest-tools$*-win install

stamps/guest-tools%-install: stamps/guest-tools%-make guest-tools32-windrv guest-tools64-windrv
	$(MAKE) -C guest-tools$* install

##########
# DECREE #
##########

stamps/decree-configure: CONFIGURE_COMMAND = cmake                                  \
                                             -DCMAKE_INSTALL_PREFIX=$(S2E_PREFIX)   \
                                             $(S2E_SRC)/decree

stamps/decree-make: stamps/decree-configure

stamps/decree-install: stamps/decree-make
	$(MAKE) -C decree install
	touch $@
