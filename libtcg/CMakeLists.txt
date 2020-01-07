# Copyright (c) 2017 Cyberhaven
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

cmake_minimum_required(VERSION 3.4.3)

project(LIBTCG)
set(LIBTCG_VERSION_MAJOR 4)
set(LIBTCG_VERSION_MINOR 0)
set(LIBTCG_VERSION_PATCH 0)
set(LIBTCG_PACKAGE_VERSION
    "${LIBTCG_VERSION_MAJOR}.${LIBTCG_VERSION_MINOR}.${LIBTCG_VERSION_PATCH}")

include(CMakePackageConfigHelpers)
set(CMAKE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Version.cmake")
write_basic_package_version_file(${CMAKE_VERSION_FILE}
                                 VERSION ${LIBTCG_PACKAGE_VERSION}
                                 COMPATIBILITY AnyNewerVersion)

set(CMAKE_CONFIG_FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake")
set(LIBTCG_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/include")
set(LIBTCG_LIBRARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/src")
configure_file(LIBTCGConfig.cmake.in ${CMAKE_CONFIG_FILE} @ONLY)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB_PKG glib-2.0)

find_package(LIBQ REQUIRED)
message(STATUS "Found libq ${LIBQ_PACKAGE_VERSION}")

##### LLVM #####
find_package(LLVM REQUIRED)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")

add_definitions(${LLVM_DEFINITIONS})

include_directories("include"
                    ${LLVM_INCLUDE_DIRS})

llvm_map_components_to_libnames(LLVM_LIBS core)

set(LLVM_CONFIG "${LLVM_TOOLS_BINARY_DIR}/llvm-config"
    CACHE PATH "Path to llvm-config")
execute_process(COMMAND ${LLVM_CONFIG} "--cxxflags"
                RESULT_VARIABLE LLVM_CONFIG_RESULT
                OUTPUT_VARIABLE LLVM_CXXFLAGS
                OUTPUT_STRIP_TRAILING_WHITESPACE)

##################

option(WITH_GUEST "Type of guest target to support")

if(NOT WITH_GUEST)
    message(FATAL_ERROR "Please specify guest target type")
endif()

message(STATUS "WITH_GUEST: ${WITH_GUEST}")

if(WITH_GUEST MATCHES "i386")
    set(TARGET_LONG_BITS "32")
    set(TARGET_INSN_START_EXTRA_WORDS "1")
elseif(WITH_GUEST MATCHES "x86_64")
    set(TARGET_LONG_BITS "64")
    set(TARGET_INSN_START_EXTRA_WORDS "1")
    set(TARGET_X86_64 "1")
else()
    message(FATAL_ERROR "Incorrect target ${WITH_GUEST}")
endif()

if(WITH_GUEST MATCHES "s2e")
    set(WITH_SYMBEX ON)
    if(NOT (WITH_GUEST MATCHES "s2e_sp"))
        set(WITH_SYMBEX_MP ON)
    endif()
endif()

include_directories(${GLIB_PKG_INCLUDE_DIRS} ${LIBTCG_INCLUDE_DIR} ${LIBQ_INCLUDE_DIR})
add_subdirectory(src)
