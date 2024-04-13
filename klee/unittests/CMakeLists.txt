#===------------------------------------------------------------------------===#
#
#                     The KLEE Symbolic Virtual Machine
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#

enable_testing()
find_package(GTest REQUIRED)

# This keeps track of all the unit test
# targets so we can ensure they are built
# before trying to run them.
define_property(GLOBAL
  PROPERTY KLEE_UNIT_TEST_TARGETS
  BRIEF_DOCS "KLEE unit tests"
  FULL_DOCS "KLEE unit tests"
)

llvm_map_components_to_libnames(LLVM_LIBS core)

set(LIBS ${LIBS} ${LLVM_LIBS} ${GTEST_LIBRARIES} ${GMOCK_LIBRARIES} gmock)

function(add_klee_unit_test target_name)
  add_executable(${target_name} ${ARGN} ${PROJECT_SOURCE_DIR}/unittests/TestMain.cpp)
  target_link_libraries(${target_name} PRIVATE ${LIBS})
  target_include_directories(${target_name} BEFORE PRIVATE "${GTEST_INCLUDE_DIR}")
  target_include_directories(${target_name} BEFORE PRIVATE "${GMOCK_INCLUDE_DIR}")
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
add_subdirectory(Utils)
add_subdirectory(Core)

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
