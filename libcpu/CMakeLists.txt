# Copyright 2016 - Cyberhaven
# This work is licensed under the terms of the GNU LGPL, version 2.1 or later.

cmake_minimum_required(VERSION 3.4.3)

project(LIBCPU)
set(LIBCPU_VERSION_MAJOR 1)
set(LIBCPU_VERSION_MINOR 0)
set(LIBCPU_VERSION_PATCH 50)
set(LIBCPU_PACKAGE_VERSION
    "${LIBCPU_VERSION_MAJOR}.${LIBCPU_VERSION_MINOR}.${LIBCPU_VERSION_PATCH}")

include(CMakePackageConfigHelpers)
set(CMAKE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Version.cmake")
write_basic_package_version_file(${CMAKE_VERSION_FILE}
                                 VERSION ${LIBCPU_PACKAGE_VERSION}
                                 COMPATIBILITY AnyNewerVersion)

set(CMAKE_CONFIG_FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake")
set(LIBCPU_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/include" "${CMAKE_BINARY_DIR}/include")
set(LIBCPU_LIBRARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/src")
configure_file(LIBCPUConfig.cmake.in ${CMAKE_CONFIG_FILE} @ONLY)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB_PKG glib-2.0)
pkg_check_modules(CAPSTONE REQUIRED capstone)


find_package(LIBQ REQUIRED)
message(STATUS "Found libq ${LIBQ_PACKAGE_VERSION}")

find_package(LIBTCG REQUIRED)
message(STATUS "Found libtcg ${LIBTCG_PACKAGE_VERSION}")

option(WITH_SYMBEX "with(out) external symbolic execution engine support")
option(WITH_TARGET "i386-softmmu, etc.")

set(S2EGUEST_INCLUDE_DIR CACHE STRING "path to S2E guest include directory")

set(CONFIG_HOST_H "${CMAKE_BINARY_DIR}/include/cpu/config-host.h")
file(WRITE ${CONFIG_HOST_H}
"
#define HOST_X86_64 1
#define CONFIG_LINUX 1
#define CONFIG_LIBCPU_DATADIR \"${CONFIG_LIBCPU_DATADIR}\"
#define LIBCPU_VERSION \"1.0.50\"
#define CONFIG_DATE \"${CONFIG_DATE}\"
#define LIBCPU_REVISION \"${LIBCPU_REVISION}\"
"
)

set(CONFIG_TARGET_H "${CMAKE_BINARY_DIR}/include/cpu/config-target.h")
file(WRITE ${CONFIG_TARGET_H}
"
#define TARGET_SHORT_ALIGNMENT 2
#define TARGET_INT_ALIGNMENT 4
#define TARGET_LLONG_ALIGNMENT 8
#define TARGET_I386 1
#define TARGET_PHYS_ADDR_BITS 64
#define CONFIG_SOFTMMU 1
#define CONFIG_I386_DIS 1
#define CONFIG_INT128 1
"
)

if (S2EGUEST_INCLUDE_DIR)
    file(APPEND ${CONFIG_TARGET_H} "#define CONFIG_SYMBEX_OPCODES 1\n")
endif()

if(NOT WITH_TARGET)
    message(FATAL_ERROR "Please specify target type")
endif()

message(STATUS "WITH_TARGET: ${WITH_TARGET}")

if(WITH_TARGET MATCHES "i386")
    file(APPEND ${CONFIG_TARGET_H} "#define TARGET_ARCH \"i386\"\n")
    file(APPEND ${CONFIG_TARGET_H} "#define TARGET_LONG_ALIGNMENT 4\n")
    file(APPEND ${CONFIG_TARGET_H} "#define TARGET_INSN_START_EXTRA_WORDS 1\n")
elseif(WITH_TARGET MATCHES "x86_64")
    file(APPEND ${CONFIG_TARGET_H} "#define TARGET_ARCH \"x86_64\"\n")
    file(APPEND ${CONFIG_TARGET_H} "#define TARGET_X86_64 1\n")
    file(APPEND ${CONFIG_TARGET_H} "#define TARGET_LONG_ALIGNMENT 8\n")
    file(APPEND ${CONFIG_TARGET_H} "#define TARGET_INSN_START_EXTRA_WORDS 1\n")
else()
    message(FATAL_ERROR "Incorrect target ${WITH_TARGET}")
endif()

if(WITH_TARGET MATCHES "s2e")
    file(APPEND ${CONFIG_TARGET_H} "#define CONFIG_SYMBEX 1\n")
    set(WITH_SYMBEX ON)
    if(NOT (WITH_TARGET MATCHES "s2e_sp"))
        file(APPEND ${CONFIG_TARGET_H} "#define CONFIG_SYMBEX_MP 1\n")
        set(WITH_SYMBEX_MP ON)
    endif()
endif()

# We want to keep NDEBUG in all builds
foreach (flags_var_to_scrub
    CMAKE_CXX_FLAGS_RELEASE
    CMAKE_CXX_FLAGS_RELWITHDEBINFO
    CMAKE_CXX_FLAGS_MINSIZEREL
    CMAKE_C_FLAGS_RELEASE
    CMAKE_C_FLAGS_RELWITHDEBINFO
    CMAKE_C_FLAGS_MINSIZEREL)
string (REGEX REPLACE "(^| )[/-]D *NDEBUG($| )" " "
    "${flags_var_to_scrub}" "${${flags_var_to_scrub}}")
endforeach()

include_directories(${GLIB_PKG_INCLUDE_DIRS}
                    ${LIBQ_INCLUDE_DIR}
                    ${CAPSTONE_INCLUDE_DIRS}
                    ${LIBTCG_INCLUDE_DIR}
                    ${HOST_INCLUDE_DIR}
                    ${TARGET_INCLUDE_DIR}
                    ${S2EGUEST_INCLUDE_DIR})

add_subdirectory(src)
