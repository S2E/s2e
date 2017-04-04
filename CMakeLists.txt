# Copyright (C) 2017, Cyberhaven
# All rights reserved.
#
# Licensed under the Cyberhaven Research License Agreement.

cmake_minimum_required(VERSION 3.4.3)

project(LIBS2EPLUGINS)
set(LIBS2EPLUGINS_VERSION_MAJOR 2)
set(LIBS2EPLUGINS_VERSION_MINOR 0)
set(LIBS2EPLUGINS_VERSION_PATCH 0)
set(LIBS2EPLUGINS_PACKAGE_VERSION
    "${LIBS2EPLUGINS_VERSION_MAJOR}.${LIBS2EPLUGINS_VERSION_MINOR}.${LIBS2EPLUGINS_VERSION_PATCH}")

include(CMakePackageConfigHelpers)
set(CMAKE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Version.cmake")
write_basic_package_version_file(${CMAKE_VERSION_FILE}
                                 VERSION ${LIBS2EPLUGINS_PACKAGE_VERSION}
                                 COMPATIBILITY AnyNewerVersion)

set(CMAKE_CONFIG_FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake")
set(LIBS2EPLUGINS_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/include")
set(LIBS2EPLUGINS_LIBRARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/src")
configure_file(LIBS2EPLUGINSConfig.cmake.in ${CMAKE_CONFIG_FILE} @ONLY)

find_package(PkgConfig REQUIRED)

pkg_check_modules(GLIB_PKG glib-2.0)
include_directories(${GLIB_PKG_INCLUDE_DIRS})

##### LLVM #####
find_package(LLVM REQUIRED)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")

add_definitions(${LLVM_DEFINITIONS})

include_directories("include" ${LLVM_INCLUDE_DIRS})

llvm_map_components_to_libnames(LLVM_LIBS core)

set(LLVM_CONFIG "${LLVM_TOOLS_BINARY_DIR}/llvm-config"
    CACHE PATH "Path to llvm-config")
execute_process(COMMAND ${LLVM_CONFIG} "--cxxflags"
                RESULT_VARIABLE LLVM_CONFIG_RESULT
                OUTPUT_VARIABLE LLVM_CXXFLAGS
                OUTPUT_STRIP_TRAILING_WHITESPACE)

##################

find_package(LIBQ REQUIRED)
message(STATUS "Found libq ${LIBQ_PACKAGE_VERSION}")

find_package(LIBCPU REQUIRED)
message(STATUS "Found libcpu ${LIBCPU_PACKAGE_VERSION}")

find_package(LIBTCG REQUIRED)
message(STATUS "Found libtcg ${LIBTCG_PACKAGE_VERSION}")

find_package(FSIGCXX REQUIRED)
message(STATUS "Found fsigc++ ${FSIGCXX_PACKAGE_VERSION}")

find_package(VMI REQUIRED)
message(STATUS "Found libvmi ${VMI_PACKAGE_VERSION}")

find_package(LIBS2ECORE REQUIRED)
message(STATUS "Found s2e core ${LIBS2ECORE_PACKAGE_VERSION}")

# TODO: proper package cfg for KLEE
# find_package(KLEE REQUIRED)
# message(STATUS "Found klee ${KLEE_PACKAGE_VERSION}")

include_directories(${GLIB_PKG_INCLUDE_DIRS}
                    ${LIBQ_INCLUDE_DIR}
                    ${LIBTCG_INCLUDE_DIR}
                    ${LIBCPU_INCLUDE_DIR}
                    ${VMI_INCLUDE_DIR}
                    ${LIBS2ECORE_INCLUDE_DIR}
                    ${LIBS2EPLUGINS_INCLUDE_DIR}
                    ${FSIGCXX_INCLUDE_DIR}
                    ${KLEE_DIR}/include
                    ${LUA_DIR}
                    ${S2EGUEST_INCLUDE_DIR})

add_subdirectory(src)
