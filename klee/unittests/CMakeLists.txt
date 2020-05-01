#===------------------------------------------------------------------------===#
#
#                     The KLEE Symbolic Virtual Machine
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#

if (NOT EXISTS "${GTEST_ROOT}")
  message(FATAL_ERROR "GTest source directory \"${GTEST_ROOT}\" cannot be found.\n"
    "Try passing -DGTEST_DIR=<path_to_gtest_source> to cmake where "
    "<path_to_gtest_source> is the path to the GoogleTest source tree.\n"
    "Alternatively you can disable unit tests by passing "
    "-DENABLE_UNIT_TESTS=OFF to cmake.")
endif()

# It's important that GTest is built with KLEE's compile flags
# so set them here.
set(_OLD_CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
foreach (f ${KLEE_COMPONENT_CXX_FLAGS})
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${f}")
endforeach()
foreach (f ${KLEE_COMPONENT_CXX_DEFINES})
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${f}")
endforeach()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

set(GTEST_INCLUDE_DIR "${GTEST_SRC}/googletest/include")
find_package(GTest REQUIRED)

set(CMAKE_CXX_FLAGS "${_OLD_CMAKE_CXX_FLAGS}") # Restore the flags

# This keeps track of all the unit test
# targets so we can ensure they are built
# before trying to run them.
define_property(GLOBAL
  PROPERTY KLEE_UNIT_TEST_TARGETS
  BRIEF_DOCS "KLEE unit tests"
  FULL_DOCS "KLEE unit tests"
)

if (NOT IS_DIRECTORY "${GTEST_INCLUDE_DIR}")
  message(FATAL_ERROR
    "Cannot find GTest include directory \"${GTEST_INCLUDE_DIR}\"")
endif()


function(add_klee_unit_test target_name)
  add_executable(${target_name} ${ARGN})
  target_link_libraries(${target_name} PRIVATE gtest_main)
  target_include_directories(${target_name} BEFORE PRIVATE "${GTEST_INCLUDE_DIR}")
  set_target_properties(${target_name}
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/unittests/"
  )
  set_property(GLOBAL
    APPEND
    PROPERTY KLEE_UNIT_TEST_TARGETS
    ${target_name}
  )
endfunction()

# Unit Tests
add_subdirectory(Expr)
add_subdirectory(ADT)

# Set up lit configuration
set (UNIT_TEST_EXE_SUFFIX "Test")
configure_file(lit-unit-tests-common.site.cfg.in
  ${CMAKE_CURRENT_BINARY_DIR}/lit.site.cfg
  @ONLY)

# Add a target to run all the unit tests using lit
get_property(UNIT_TEST_DEPENDS
  GLOBAL
  PROPERTY KLEE_UNIT_TEST_TARGETS
)
add_custom_target(unittests
  COMMAND
    "${LIT_TOOL}" ${LIT_ARGS} "${CMAKE_CURRENT_BINARY_DIR}"
    DEPENDS ${UNIT_TEST_DEPENDS}
    COMMENT "Running unittests"
    ${ADD_CUSTOM_COMMAND_USES_TERMINAL_ARG}
)
