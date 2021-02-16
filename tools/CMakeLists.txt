# Copyright (c) 2017 Dependable Systems Laboratory, EPFL
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

project(s2etools)
set(s2etools_VERSION_MAJOR 1)
set(s2etools_VERSION_MINOR 0)
set(s2etools_VERSION_PATCH 0)
set(s2etools_PACKAGE_VERSION
    "${s2etools_VERSION_MAJOR}.${s2etools_VERSION_MINOR}.${s2etools_VERSION_PATCH}")

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR})
message(STATUS "CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}")
include(CMakePackageConfigHelpers)
set(CMAKE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Version.cmake")
write_basic_package_version_file(${CMAKE_VERSION_FILE}
                                 VERSION ${s2etools_PACKAGE_VERSION}
                                 COMPATIBILITY AnyNewerVersion)

include(FindPkgConfig)
pkg_check_modules(GLIB2 glib-2.0)

set(Protobuf_USE_STATIC_LIBS ON)
include(FindProtobuf)
find_package(Protobuf REQUIRED)

# Old CMake does not support static libraries, so we have to patch the library manually
string(REPLACE .so .a PROTOBUF_LIBRARIES "${PROTOBUF_LIBRARIES}")

find_package(LLVM REQUIRED)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")

find_package(VMI REQUIRED)
message(STATUS "Found VMI ${VMI_PACKAGE_VERSION}")

find_package(FSIGCXX REQUIRED)
message(STATUS "Found fsigc++ ${FSIGCXX_PACKAGE_VERSION}")

find_package(LIBQ REQUIRED)
message(STATUS "Found libq ${LIBQ_PACKAGE_VERSION}")

if(LIBCPU_SRC_DIR)
  message(STATUS "libcpu source directory: ${LIBCPU_SRC_DIR}")
else()
 message(FATAL_ERROR "No libcpu source directory specified")
endif()

if(LIBTCG_SRC_DIR)
  message(STATUS "libtcg source directory: ${LIBTCG_SRC_DIR}")
else()
 message(FATAL_ERROR "No libtcg source directory specified")
endif()

if(S2EPLUGINS_SRC_DIR)
  message(STATUS "S2E plugins source directory: ${S2EPLUGINS_SRC_DIR}")
else()
 message(FATAL_ERROR "No S2E plugins source directory specified")
endif()

if(NOT LIBCPU_TARGET)
  set(LIBCPU_TARGET "i386" CACHE STRING "libcpu target")
endif()

add_definitions(${LLVM_DEFINITIONS})

include_directories("include"
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${LLVM_INCLUDE_DIRS}
                    ${LIBCPU_SRC_DIR}
                    ${S2EPLUGINS_SRC_DIR}
                    ${VMI_INCLUDE_DIR}
                    ${LIBQ_INCLUDE_DIR}
                    ${FSIGCXX_INCLUDE_DIR}
                    ${PROTOBUF_INCLUDE_DIRS})

link_directories(${VMI_LIBRARY_DIR} ${FSIGCXX_LIBRARY_DIR} ${LIBQ_LIBRARY_DIR})

llvm_map_components_to_libnames(LLVM_LIBS core
                                          debuginfodwarf
                                          ipo
                                          bitwriter
                                          mcjit
                                          x86codegen
                                          x86desc
                                          x86info)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -Wall -Werror")

add_subdirectory(lib)
add_subdirectory(tools)
