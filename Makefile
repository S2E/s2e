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

# More recent point releases don't have the Ubuntu binaries yet, so stick with 14.0.0.
LLVM_VERSION=14.0.0
LLVM_SRC=llvm-$(LLVM_VERSION).src.tar.xz
LLVM_SRC_DIR=llvm-$(LLVM_VERSION).src
LLVM_SRC_URL=https://github.com/llvm/llvm-project/releases/download/llvmorg-$(LLVM_VERSION)/

# The Python script should only return a single word - the suffix of the Clang
# binary to download. If an error message is printed to stderr, the Makefile
# error will be triggered.
CLANG_BINARY_SUFFIX=$(shell $(BUILD_SCRIPTS_SRC)/determine_clang_binary_suffix.py 2>&1)
ifneq ($(words $(CLANG_BINARY_SUFFIX)), 1)
$(error "Failed to determine Clang binary to download: $(CLANG_BINARY_SUFFIX)")
endif

KLEE_DIRS=$(foreach suffix,-debug -release,$(addsuffix $(suffix),klee))

CLANG_BINARY_DIR=clang+llvm-$(LLVM_VERSION)-$(CLANG_BINARY_SUFFIX)
CLANG_BINARY=$(CLANG_BINARY_DIR).tar.xz

CLANG_SRC=clang-$(LLVM_VERSION).src.tar.xz
CLANG_SRC_DIR=clang-$(LLVM_VERSION).src
CLANG_DEST_DIR=$(LLVM_SRC_DIR)/tools/clang

COMPILER_RT_SRC=compiler-rt-$(LLVM_VERSION).src.tar.xz
COMPILER_RT_SRC_DIR=compiler-rt-$(LLVM_VERSION).src
COMPILER_RT_DEST_DIR=$(LLVM_SRC_DIR)/projects/compiler-rt

# Capstone variables
CAPSTONE_VERSION=4.0.2
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
Z3_BINARY_URL=https://github.com/Z3Prover/z3/releases/download/z3-$(Z3_VERSION)/
Z3_BINARY=z3-$(Z3_VERSION)-x64-ubuntu-16.04.zip
Z3_BINARY_DIR=z3-$(Z3_VERSION)-x64-ubuntu-16.04

# Lua variables
LUA_VERSION=5.3.4
LUA_SRC=lua-$(LUA_VERSION).tar.gz
LUA_DIR=lua-$(LUA_VERSION)

# SOCI variables
SOCI_SRC_DIR=soci-src
SOCI_BUILD_DIR=soci
SOCI_GIT_REV=438e354
SOCI_GIT_URL=https://github.com/SOCI/soci.git

# Google Test
GTEST_VERSION=1.11.0
GTEST_SRC_DIR=$(S2E_BUILD)/gtest-src
GTEST_BUILD_DIR=$(S2E_BUILD)/gtest-release
GTEST_URL=https://github.com/google/googletest/archive/release-$(GTEST_VERSION).tar.gz

# libdwarf
# We don't use the one that ships with the distro because we need
# the latest features (PE file support mostly).
LIBDWARF_URL=https://www.prevanders.net/libdwarf-20190110.tar.gz
LIBDWARF_SRC_DIR=libdwarf-20190110
LIBDWARF_BUILD_DIR=libdwarf

# rapidjson
# We don't use the one that ships with the distro because we need
# the latest features.
RAPIDJSON_GIT_URL=https://github.com/Tencent/rapidjson.git
RAPIDJSON_GIT_REV=fd3dc29a5c2852df569e1ea81dbde2c412ac5051
RAPIDJSON_SRC_DIR=rapidjson
RAPIDJSON_BUILD_DIR=rapidjson-build

# protobuf
# We build our own because the one on Ubuntu 16 crashes.
PROTOBUF_URL=https://github.com/protocolbuffers/protobuf/releases/download/v3.7.1/protobuf-cpp-3.7.1.tar.gz
PROTOBUF_SRC_DIR=protobuf-3.7.1
PROTOBUF_BUILD_DIR=protobuf


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
    guest-tools-win-install stamps/llvm-release-install
install-debug: all-debug stamps/libs2e-debug-install stamps/tools-debug-install \
    stamps/libvmi-debug-install guest-tools-install       \
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


ifeq ($(LLVM_BUILD),$(S2E_BUILD))
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

else
# Use the specified LLVM build folder, don't build LLVM
endif

# Download Lua
$(LUA_SRC):
	$(call DOWNLOAD,https://www.lua.org/ftp/$(LUA_SRC),$@)

$(LUA_DIR): | $(LUA_SRC)
	tar -zxf $(LUA_SRC)
	cp $(S2E_SRC)/lua/luaconf.h $(LUA_DIR)/src

# Download Z3
$(Z3_BUILD_DIR):
	$(call DOWNLOAD,$(Z3_URL)/archive/$(Z3_SRC),$(Z3_SRC))
	tar -zxf $(Z3_SRC)
	mkdir -p $(S2E_BUILD)/$(Z3_BUILD_DIR)

# Download SOCI
$(SOCI_BUILD_DIR):
	git clone $(SOCI_GIT_URL) $(SOCI_SRC_DIR)
	cd $(SOCI_SRC_DIR) && git checkout $(SOCI_GIT_REV)
	mkdir -p $(S2E_BUILD)/$(SOCI_BUILD_DIR)

# Download GTest
$(GTEST_BUILD_DIR):
	mkdir -p "$(GTEST_SRC_DIR)"
	cd $(S2E_BUILD) && wget -O $(GTEST_SRC_DIR).tar.gz $(GTEST_URL) || rm -f "$@"
	cd $(S2E_BUILD) && tar xzvf $(GTEST_SRC_DIR).tar.gz -C $(GTEST_SRC_DIR) --strip-components=1
	mkdir -p "$@"

# Download Capstone
$(CAPSTONE_BUILD_DIR):
	$(call DOWNLOAD,$(CAPSTONE_URL),$(CAPSTONE_SRC_DIR).tar.gz)
	tar -zxf $(CAPSTONE_SRC_DIR).tar.gz
	mkdir -p $(S2E_BUILD)/$(CAPSTONE_BUILD_DIR)

$(LIBDWARF_BUILD_DIR):
	$(call DOWNLOAD,$(LIBDWARF_URL),$(S2E_BUILD)/$(LIBDWARF_BUILD_DIR).tar.gz)
	tar -zxf $(S2E_BUILD)/$(LIBDWARF_BUILD_DIR).tar.gz
	mkdir -p $(S2E_BUILD)/$(LIBDWARF_BUILD_DIR)

$(RAPIDJSON_BUILD_DIR):
	git clone $(RAPIDJSON_GIT_URL) $(RAPIDJSON_SRC_DIR)
	cd $(RAPIDJSON_SRC_DIR) && git checkout $(RAPIDJSON_GIT_REV)
	mkdir -p $(S2E_BUILD)/$(RAPIDJSON_BUILD_DIR)

$(PROTOBUF_BUILD_DIR):
	$(call DOWNLOAD,$(PROTOBUF_URL),$(S2E_BUILD)/$(PROTOBUF_SRC_DIR).tar.gz)
	tar -zxf $(S2E_BUILD)/$(PROTOBUF_SRC_DIR).tar.gz
	mkdir -p $(S2E_BUILD)/$(PROTOBUF_BUILD_DIR)

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
                                                 $(LLVM_BUILD)/$(LLVM_SRC_DIR)

stamps/llvm-release-configure: stamps/clang-binary $(LLVM_SRC_DIR)
stamps/llvm-release-configure: CONFIGURE_COMMAND = cmake $(LLVM_CONFIGURE_FLAGS)           \
                                                   -DCMAKE_BUILD_TYPE=Release              \
                                                   -DCMAKE_CXX_FLAGS="$(CXXFLAGS_RELEASE)" \
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
                       -DSOCI_TESTS=Off                     \
                       -DCMAKE_C_FLAGS="-fPIC"              \
                       -G "Unix Makefiles"

stamps/soci-configure: stamps/clang-binary $(SOCI_BUILD_DIR)
stamps/soci-configure: CONFIGURE_COMMAND = cmake $(SOCI_CONFIGURE_FLAGS)    \
                                           $(S2E_BUILD)/$(SOCI_SRC_DIR)

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

############
# libdwarf #
############

stamps/libdwarf-configure: stamps/clang-binary $(LIBDWARF_BUILD_DIR)
	cd $(LIBDWARF_BUILD_DIR) &&                                         \
	CC=$(CLANG_CC) CXX=$(CLANG_CXX) $(S2E_BUILD)/$(LIBDWARF_SRC_DIR)/configure --prefix=$(S2E_PREFIX)
	touch $@

stamps/libdwarf-make: stamps/libdwarf-configure
	$(MAKE) -C $(LIBDWARF_BUILD_DIR)
	$(MAKE) -C $(LIBDWARF_BUILD_DIR) install
	touch $@

#############
# rapidjson #
#############

RAPIDJSON_CONFIGURE_FLAGS = -DCMAKE_INSTALL_PREFIX=$(S2E_PREFIX)                                 \
                            -DCMAKE_C_FLAGS="$(CFLAGS_ARCH) -fno-omit-frame-pointer -fPIC"       \
                            -DCMAKE_C_COMPILER=$(CLANG_CC)                                       \
                            -DCMAKE_CXX_COMPILER=$(CLANG_CXX)                                    \
                            -DRAPIDJSON_BUILD_TESTS=OFF


stamps/rapidjson-configure: stamps/clang-binary $(RAPIDJSON_BUILD_DIR)
	cd $(RAPIDJSON_BUILD_DIR) &&                                         \
	cmake $(RAPIDJSON_CONFIGURE_FLAGS) $(S2E_BUILD)/$(RAPIDJSON_SRC_DIR)
	touch $@

stamps/rapidjson-make: stamps/rapidjson-configure
	$(MAKE) -C $(RAPIDJSON_BUILD_DIR) install
	touch $@

############
# protobuf #
############

stamps/protobuf-configure: stamps/clang-binary $(PROTOBUF_BUILD_DIR)
	cd $(PROTOBUF_BUILD_DIR) &&                                         \
	CC=$(CLANG_CC) CXX=$(CLANG_CXX) CXXFLAGS=-fPIC CFLAGS=-fPIC $(S2E_BUILD)/$(PROTOBUF_SRC_DIR)/configure --prefix=$(S2E_PREFIX)
	touch $@

stamps/protobuf-make: stamps/protobuf-configure
	$(MAKE) -C $(PROTOBUF_BUILD_DIR) install
	touch $@


#######
# Lua #
#######

stamps/lua-make: $(LUA_DIR)
	if [ "$(PLATFORM)" = "linux" ]; then \
		$(SED) -i 's/-lreadline//g' $(LUA_DIR)/src/Makefile; \
		$(MAKE) -C $^ linux CFLAGS="-DLUA_USE_LINUX -O2 -g -fPIC"; \
	elif [ "$(PLATFORM)" = "darwin" ]; then \
		$(MAKE) -C $^ macosx CFLAGS="-DLUA_USE_LINUX -O2 -g -fPIC"; \
	fi
	touch $@

#########
# GTest #
#########

stamps/gtest-release-configure: stamps/clang-binary $(GTEST_BUILD_DIR)
	cd $(GTEST_BUILD_DIR) && cmake -DCMAKE_C_COMPILER=$(CLANG_CC) \
	-DCMAKE_CXX_COMPILER=$(CLANG_CXX)  \
	$(GTEST_SRC_DIR)
	touch $@

stamps/gtest-release-make: stamps/gtest-release-configure
	$(MAKE) -C $(GTEST_BUILD_DIR)
	touch $@


########
# KLEE #
########

KLEE_CONFIGURE_FLAGS = -DCMAKE_INSTALL_PREFIX=$(S2E_PREFIX)                                 \
                       -DCMAKE_C_FLAGS="$(CFLAGS_ARCH) -fno-omit-frame-pointer -fPIC"       \
                       -DCMAKE_C_COMPILER=$(CLANG_CC)                                       \
                       -DCMAKE_CXX_COMPILER=$(CLANG_CXX)                                    \
                       -DENABLE_UNIT_TESTS=On                                               \
                       -DGTEST_SRC=$(GTEST_SRC_DIR)                                         \
                       -DGTEST_ROOT=$(GTEST_BUILD_DIR)                                      \
                       -DENABLE_DOCS=Off                                                    \
                       -DENABLE_SOLVER_Z3=On                                                \
                       -DZ3_INCLUDE_DIRS=$(S2E_PREFIX)/include                              \
                       -DZ3_LIBRARIES=$(S2E_PREFIX)/lib/libz3.a

stamps/klee-debug-configure: stamps/llvm-debug-make stamps/z3 stamps/gtest-release-make $(call FIND_CONFIG_SOURCE,$(S2E_SRC)/klee)
stamps/klee-debug-configure: CONFIGURE_COMMAND = cmake $(KLEE_CONFIGURE_FLAGS)                      \
                                                 -DCMAKE_BUILD_TYPE=Debug                           \
                                                 -DLLVM_DIR=$(LLVM_BUILD)/llvm-debug/lib/cmake/llvm \
                                                 -DCMAKE_CXX_FLAGS="$(CXXFLAGS_DEBUG) -fno-omit-frame-pointer -fPIC" \
                                                 $(S2E_SRC)/klee

stamps/klee-release-configure: stamps/llvm-release-make stamps/z3 stamps/gtest-release-make $(call FIND_CONFIG_SOURCE,$(S2E_SRC)/klee)
stamps/klee-release-configure: CONFIGURE_COMMAND = cmake $(KLEE_CONFIGURE_FLAGS)                        \
                                                   -DCMAKE_BUILD_TYPE=$(RELEASE_BUILD_TYPE)             \
                                                   -DLLVM_DIR=$(LLVM_BUILD)/llvm-release/lib/cmake/llvm \
                                                   -DCMAKE_CXX_FLAGS="$(CXXFLAGS_RELEASE) -fno-omit-frame-pointer -fPIC" \
                                                   $(S2E_SRC)/klee

stamps/klee-debug-make: stamps/klee-debug-configure $(call FIND_SOURCE,$(S2E_SRC)/klee)

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

stamps/libvmi-debug-configure: stamps/llvm-debug-make stamps/libdwarf-make stamps/rapidjson-make $(call FIND_CONFIG_SOURCE,$(S2E_SRC)/libvmi)
stamps/libvmi-debug-configure: CONFIGURE_COMMAND = cmake $(LIBVMI_COMMON_FLAGS)                         \
                                                   -DLLVM_DIR=$(LLVM_BUILD)/llvm-debug/lib/cmake/llvm   \
                                                   -DCMAKE_BUILD_TYPE=Debug                             \
                                                   -DCMAKE_CXX_FLAGS="$(CXXFLAGS_DEBUG) -fPIC"          \
                                                   $(S2E_SRC)/libvmi

stamps/libvmi-release-configure: stamps/llvm-release-make stamps/libdwarf-make stamps/rapidjson-make $(call FIND_CONFIG_SOURCE,$(S2E_SRC)/libvmi)
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

stamps/libfsigc++-debug-configure: stamps/clang-binary $(call FIND_CONFIG_SOURCE,$(S2E_SRC)/libfsigc++)

stamps/libfsigc++-debug-configure: CONFIGURE_COMMAND = cmake $(LIBFSIGCXX_COMMON_FLAGS) \
                                                       -DCMAKE_BUILD_TYPE=Debug         \
                                                       -DCMAKE_CXX_FLAGS="$(CXXFLAGS_DEBUG)" \
                                                       $(S2E_SRC)/libfsigc++


stamps/libfsigc++-release-configure: stamps/clang-binary $(call FIND_CONFIG_SOURCE,$(S2E_SRC)/libfsigc++)

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

stamps/libq-debug-configure: stamps/clang-binary $(call FIND_CONFIG_SOURCE,$(S2E_SRC)/libq)

stamps/libq-debug-configure: CONFIGURE_COMMAND = cmake $(LIBQ_COMMON_FLAGS) \
                                                 -DCMAKE_BUILD_TYPE=Debug   \
                                                 -DCMAKE_CXX_FLAGS="$(CXXFLAGS_DEBUG)" \
                                                 $(S2E_SRC)/libq


stamps/libq-release-configure: stamps/clang-binary $(call FIND_CONFIG_SOURCE,$(S2E_SRC)/libq)

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

stamps/libcoroutine-debug-configure: stamps/clang-binary $(call FIND_CONFIG_SOURCE,$(S2E_SRC)/libcoroutine)

stamps/libcoroutine-debug-configure: CONFIGURE_COMMAND = cmake $(LIBCOROUTINE_COMMON_FLAGS)    \
                                                         -DCMAKE_BUILD_TYPE=Debug              \
                                                         -DCMAKE_CXX_FLAGS="$(CXXFLAGS_DEBUG)" \
                                                         $(S2E_SRC)/libcoroutine


stamps/libcoroutine-release-configure: stamps/clang-binary $(call FIND_CONFIG_SOURCE,$(S2E_SRC)/libcoroutine)

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
                         --with-capstone-incdir=$(S2E_PREFIX)/include               \
                         --with-capstone-libdir=$(S2E_PREFIX)/lib                   \
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
    stamps/klee-debug-make stamps/soci-make stamps/libfsigc++-debug-make        \
    stamps/libq-debug-make stamps/libcoroutine-debug-make stamps/capstone-make  \
    stamps/protobuf-make
stamps/libs2e-debug-configure: CONFIGURE_COMMAND = $(S2E_SRC)/libs2e/configure  \
                                                   $(LIBS2E_CONFIGURE_FLAGS)    \
                                                   $(LIBS2E_DEBUG_FLAGS)

stamps/libs2e-release-configure: $(call FIND_CONFIG_SOURCE,$(S2E_SRC)/libs2e)
stamps/libs2e-release-configure: stamps/lua-make stamps/libvmi-release-install  \
    stamps/klee-release-make stamps/soci-make stamps/libfsigc++-release-make    \
    stamps/libq-release-make stamps/libcoroutine-release-make  stamps/capstone-make \
    stamps/protobuf-make
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
