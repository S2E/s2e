# Copyright 2016 - Cyberhaven
# This work is licensed under the terms of the GNU LGPL, version 2.1 or later.

cmake_minimum_required(VERSION 3.4.3)


project(LIBCOROUTINE)
set(LIBCOROUTINE_VERSION_MAJOR 1)
set(LIBCOROUTINE_VERSION_MINOR 0)
set(LIBCOROUTINE_VERSION_PATCH 0)
set(LIBCOROUTINE_PACKAGE_VERSION
    "${LIBCOROUTINE_VERSION_MAJOR}.${LIBCOROUTINE_VERSION_MINOR}.${LIBCOROUTINE_VERSION_PATCH}")

include(CMakePackageConfigHelpers)
set(CMAKE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Version.cmake")
write_basic_package_version_file(${CMAKE_VERSION_FILE}
                                 VERSION ${LIBCOROUTINE_PACKAGE_VERSION}
                                 COMPATIBILITY AnyNewerVersion)

set(CMAKE_CONFIG_FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake")
set(LIBCOROUTINE_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/include")
set(LIBCOROUTINE_LIBRARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/src")
configure_file(LIBCOROUTINEConfig.cmake.in ${CMAKE_CONFIG_FILE} @ONLY)


find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB_PKG glib-2.0)

include_directories(${GLIB_PKG_INCLUDE_DIRS} ${LIBCOROUTINE_INCLUDE_DIR})

add_subdirectory(src)
