# Copyright (C) 2017, Cyberhaven
# All rights reserved.
#
# Licensed under the Cyberhaven Research License Agreement.

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

include_directories("include"
                    ${LLVM_INCLUDE_DIRS})

llvm_map_components_to_libnames(LLVM_LIBS core)

set(LLVM_CONFIG "${LLVM_TOOLS_BINARY_DIR}/llvm-config"
    CACHE PATH "Path to llvm-config")
execute_process(COMMAND ${LLVM_CONFIG} "--cxxflags"
                RESULT_VARIABLE LLVM_CONFIG_RESULT
                OUTPUT_VARIABLE LLVM_CXXFLAGS
                OUTPUT_STRIP_TRAILING_WHITESPACE)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${LLVM_CXXFLAGS} -Wall -std=c++11")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror -Wno-gnu-anonymous-struct -Wno-nested-anon-types -Wno-c99-extensions -Wno-extended-offsetof")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -g -O2")

add_subdirectory(src)

add_executable(crashdump src/crashdump.cpp)
target_link_libraries(crashdump vmi ${LLVM_LIBS})

add_executable(vmidemo src/vmidemo.cpp)
target_link_libraries(vmidemo vmi dwarf elf ${LLVM_LIBS})

add_executable(injector src/injector.cpp)
target_link_libraries(injector vmi elf ${LLVM_LIBS})

add_executable(dump src/dump.cpp)
target_link_libraries(dump vmi elf ${LLVM_LIBS})

add_executable(reader src/reader.cpp)
target_link_libraries(reader vmi elf ${LLVM_LIBS})

install(TARGETS crashdump vmidemo injector dump reader
        RUNTIME DESTINATION bin)
install(DIRECTORY "include/vmi"
        DESTINATION include)
install(FILES ${CMAKE_CONFIG_FILE} ${CMAKE_VERSION_FILE}
        DESTINATION cmake
        COMPONENT Devel)
