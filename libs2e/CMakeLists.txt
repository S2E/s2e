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

project(LIBS2E)
set(LIBS2E_VERSION_MAJOR 2)
set(LIBS2E_VERSION_MINOR 0)
set(LIBS2E_VERSION_PATCH 0)
set(LIBS2E_PACKAGE_VERSION
    "${LIBS2E_VERSION_MAJOR}.${LIBS2E_VERSION_MINOR}.${LIBS2E_VERSION_PATCH}")

include(CMakePackageConfigHelpers)
set(CMAKE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Version.cmake")
write_basic_package_version_file(${CMAKE_VERSION_FILE}
                                 VERSION ${LIBS2E_PACKAGE_VERSION}
                                 COMPATIBILITY AnyNewerVersion)

set(CMAKE_CONFIG_FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake")
set(LIBS2E_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/include")
set(LIBS2E_LIBRARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/src")
configure_file(LIBS2EConfig.cmake.in ${CMAKE_CONFIG_FILE} @ONLY)

find_package(PkgConfig REQUIRED)

pkg_check_modules(GLIB_PKG glib-2.0)
include_directories(${GLIB_PKG_INCLUDE_DIRS})

set(Protobuf_USE_STATIC_LIBS ON)
include(FindProtobuf)
find_package(Protobuf REQUIRED)

# Old CMake does not support static libraries, so we have to patch the library manually
string(REPLACE .so .a PROTOBUF_LIBRARIES "${PROTOBUF_LIBRARIES}")


##### LLVM #####
find_package(LLVM REQUIRED)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")

add_definitions(${LLVM_DEFINITIONS})

include_directories("include" ${LLVM_INCLUDE_DIRS})

llvm_map_components_to_libnames(LLVM_LIBS all)

set(LLVM_CONFIG "${LLVM_TOOLS_BINARY_DIR}/llvm-config"
    CACHE PATH "Path to llvm-config")
execute_process(COMMAND ${LLVM_CONFIG} "--cxxflags"
                RESULT_VARIABLE LLVM_CONFIG_RESULT
                OUTPUT_VARIABLE LLVM_CXXFLAGS
                OUTPUT_STRIP_TRAILING_WHITESPACE)

##################

find_package(KLEE REQUIRED)
message(STATUS "Found klee ${KLEE_PACKAGE_VERSION}")

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

find_package(LIBCOROUTINE REQUIRED)
message(STATUS "Found libcoroutine ${LIBCOROUTINE_PACKAGE_VERSION}")

if(WITH_TARGET MATCHES "s2e")
    # TODO: look at libcpu compile options to figure this out§
    find_package(LIBS2ECORE REQUIRED)
    message(STATUS "Found s2e core ${LIBS2ECORE_PACKAGE_VERSION}")

    find_package(LIBS2EPLUGINS REQUIRED)
    message(STATUS "Found s2e plugins ${LIBS2EPLUGINS_PACKAGE_VERSION}")

    include_directories(${LIBS2ECORE_INCLUDE_DIR} ${LIBS2EPLUGINS_INCLUDE_DIR})
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
                    ${LIBTCG_INCLUDE_DIR}
                    ${LIBCPU_INCLUDE_DIR}
                    ${FSIGCXX_INCLUDE_DIR}
                    ${LIBQ_INCLUDE_DIR}
                    ${LIBCOROUTINE_INCLUDE_DIR}
                    ${VMI_INCLUDE_DIR})

link_directories(${GLIB_PKG_LIBRARY_DIRS}
                    ${LIBTCG_LIBRARY_DIR}
                    ${LIBCPU_LIBRARY_DIR}
                    ${LIBQ_LIBRARY_DIR}
                    ${KLEE_LIBRARY_DIR}
                    ${LUA_DIR}
                    ${Z3_DIR}
                    ${FSIGCXX_LIBRARY_DIR}
                    ${LIBCOROUTINE_LIBRARY_DIR}
                    ${LIBS2ECORE_LIBRARY_DIR}
                    ${LIBS2EPLUGINS_LIBRARY_DIR}
                    ${VMI_LIBRARY_DIR})

add_subdirectory(src)
