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

cmake_minimum_required(VERSION 3.10)

project(LIBUTILS)
set(LIBUTILS_VERSION_MAJOR 1)
set(LIBUTILS_VERSION_MINOR 0)
set(LIBUTILS_VERSION_PATCH 0)
set(LIBUTILS_PACKAGE_VERSION
    "${LIBUTILS_VERSION_MAJOR}.${LIBUTILS_VERSION_MINOR}.${LIBUTILS_VERSION_PATCH}")

include(CMakePackageConfigHelpers)
set(CMAKE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Version.cmake")
write_basic_package_version_file(${CMAKE_VERSION_FILE}
                                 VERSION ${LIBUTILS_PACKAGE_VERSION}
                                 COMPATIBILITY AnyNewerVersion)

set(CMAKE_CONFIG_FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake")
set(LIBUTILS_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/include")
set(LIBUTILS_LIBRARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/src")
configure_file(LIBUTILSConfig.cmake.in ${CMAKE_CONFIG_FILE} @ONLY)

# We want to remove NDEBUG from all builds
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

find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB_PKG glib-2.0)

include_directories(${GLIB_PKG_INCLUDE_DIRS} ${LIBUTILS_INCLUDE_DIR})

add_subdirectory(src)
