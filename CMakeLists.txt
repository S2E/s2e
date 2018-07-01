# S2E Selective Symbolic Execution Platform
#
# Copyright (c) 2017 Dependable Systems Laboratory, EPFL
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

project(guesttools)
set(guesttools_VERSION_MAJOR 0)
set(guesttools_VERSION_MINOR 1)
set(guesttools_VERSION_PATCH 0)
set(guesttools_PACKAGE_VERSION
    "${guesttools_VERSION_MAJOR}.${guesttools_VERSION_MINOR}.${guesttools_VERSION_PATCH}")

include(CMakePackageConfigHelpers)
set(CMAKE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Version.cmake")
write_basic_package_version_file(${CMAKE_VERSION_FILE}
                                 VERSION ${guesttools_PACKAGE_VERSION}
                                 COMPATIBILITY AnyNewerVersion)

include_directories("common/include")

# Determine the architecture to build for. By default build for 64-bit
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -std=c99 -Werror")
if(NOT BITS)
  set(BITS 64)
endif()
if(${BITS} EQUAL 32)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32 -march=i386 -mtune=generic")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32 -march=i386 -mtune=generic")
elseif(${BITS} EQUAL 64)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m64 -march=x86-64 -mtune=generic")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m64 -march=x86-64 -mtune=generic")
else()
  message(FATAL_ERROR "Invalid number of bits: ${BITS}. Guest must be either 32 or 64 bits")
endif()

if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
  # C++ requires special run time libraries in the guest, which we don't have.
  # Compile C++ binaries statically to make it simpler.
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static")
endif()

# Build for all systems
add_subdirectory(common)

# Only build for Linux
if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
  add_subdirectory(linux)

  set(S2EBIOS_BUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}/s2ebios")
  set(S2EBIOS_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/s2ebios")
  file(MAKE_DIRECTORY ${S2EBIOS_BUILD_DIR})
  add_custom_target(s2ebios ALL
                    COMMAND make -f ${S2EBIOS_SOURCE_DIR}/Makefile BITS=${BITS}
                    WORKING_DIRECTORY ${S2EBIOS_BUILD_DIR})
  install(FILES ${S2EBIOS_BUILD_DIR}/s2e-bios.bin DESTINATION .)
endif()
