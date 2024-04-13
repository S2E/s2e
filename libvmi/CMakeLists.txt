# Copyright (C) 2017, Cyberhaven
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

project(VMI)
set(VMI_VERSION_MAJOR 1)
set(VMI_VERSION_MINOR 0)
set(VMI_VERSION_PATCH 0)
set(VMI_PACKAGE_VERSION
    "${VMI_VERSION_MAJOR}.${VMI_VERSION_MINOR}.${VMI_VERSION_PATCH}")

include(CMakePackageConfigHelpers)
set(CMAKE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Version.cmake")
write_basic_package_version_file(${CMAKE_VERSION_FILE}
                                 VERSION ${VMI_PACKAGE_VERSION}
                                 COMPATIBILITY AnyNewerVersion)

set(CMAKE_CONFIG_FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake")
set(VMI_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/include")
set(VMI_LIBRARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/src")
configure_file(VMIConfig.cmake.in ${CMAKE_CONFIG_FILE} @ONLY)

find_package(LLVM REQUIRED)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")

add_definitions(${LLVM_DEFINITIONS})

find_package(RapidJSON REQUIRED)

set(ENV{PKG_CONFIG_PATH} ${CMAKE_INSTALL_PREFIX}/lib/pkgconfig)
find_package(PkgConfig REQUIRED)
set(CMAKE_PREFIX_PATH ${CMAKE_INSTALL_PREFIX})
pkg_check_modules(LIBDWARF REQUIRED IMPORTED_TARGET libdwarf)

find_path(LIBDWARF_INCLUDE_DIRS
          NAMES libdwarf.h dwarf.h
          HINTS ${CMAKE_INSTALL_PREFIX}/include)
message(STATUS "Found libdwarf include dir ${LIBDWARF_INCLUDE_DIRS}")

find_library(LIBDWARF_LIB
             libdwarf.a
             HINTS ${CMAKE_INSTALL_PREFIX}/lib)

# LLVM include paths should come first, because the one in /opt
# may contain LLVM include files that were built for a different
# configuration.
include_directories(${LLVM_INCLUDE_DIRS}
                    "include"
                    ${LIBDWARF_INCLUDE_DIRS}
                    ${RapidJSON_INCLUDE_DIRS})

link_directories(${LIBDWARF_LIB_DIRS})

llvm_map_components_to_libnames(LLVM_LIBS core support)

set(LLVM_CONFIG "${LLVM_TOOLS_BINARY_DIR}/llvm-config"
    CACHE PATH "Path to llvm-config")
execute_process(COMMAND ${LLVM_CONFIG} "--cxxflags"
                RESULT_VARIABLE LLVM_CONFIG_RESULT
                OUTPUT_VARIABLE LLVM_CXXFLAGS
                OUTPUT_STRIP_TRAILING_WHITESPACE)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${LLVM_CXXFLAGS} -Wall -std=c++17")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror -Wno-gnu-anonymous-struct -Wno-nested-anon-types -Wno-c99-extensions")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-address-of-packed-member")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -g -O2")

add_subdirectory(src)

add_executable(crashdump src/crashdump.cpp)
target_link_libraries(crashdump vmi ${LLVM_LIBS})

add_executable(injector src/injector.cpp)
target_link_libraries(injector vmi elf ${LLVM_LIBS})

add_executable(dump src/dump.cpp)
target_link_libraries(dump vmi elf ${LLVM_LIBS})

add_executable(reader src/reader.cpp)
target_link_libraries(reader vmi elf ${LLVM_LIBS})

add_executable(addrs2lines src/addrs2lines.cpp)
target_link_libraries(addrs2lines vmi ${LIBDWARF_LIB} elf ${LLVM_LIBS} zstd)

install(TARGETS crashdump injector dump reader addrs2lines
        RUNTIME DESTINATION bin)
install(DIRECTORY "include/vmi"
        DESTINATION include)
install(FILES ${CMAKE_CONFIG_FILE} ${CMAKE_VERSION_FILE}
        DESTINATION cmake
        COMPONENT Devel)
