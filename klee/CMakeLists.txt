#===------------------------------------------------------------------------===#
#
#                     The KLEE Symbolic Virtual Machine
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#

###############################################################################
# Minimum CMake version and policies
###############################################################################
cmake_minimum_required(VERSION 2.8.12)

project(KLEE)
set(KLEE_VERSION_MAJOR 1)
set(KLEE_VERSION_MINOR 0)
set(KLEE_VERSION_PATCH 0)
set(KLEE_PACKAGE_VERSION
    "${KLEE_VERSION_MAJOR}.${KLEE_VERSION_MINOR}.${KLEE_VERSION_PATCH}")

include(CMakePackageConfigHelpers)
set(CMAKE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Version.cmake")
write_basic_package_version_file(${CMAKE_VERSION_FILE}
                                 VERSION ${KLEE_PACKAGE_VERSION}
                                 COMPATIBILITY AnyNewerVersion)

set(CMAKE_CONFIG_FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake")
set(KLEE_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/include")
set(KLEE_LIBRARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/lib")
configure_file(KLEEConfig.cmake.in ${CMAKE_CONFIG_FILE} @ONLY)


if (POLICY CMP0054)
  # FIXME: This is horrible. With the old behaviour,
  # quoted strings like "MSVC" in if() conditionals
  # get implicitly dereferenced. The NEW behaviour
  # doesn't do this but CMP0054 was only introduced
  # in CMake 3.1 and we support lower versions as the
  # minimum. We could set NEW here but it would be very
  # confusing to use NEW for some builds and OLD for others
  # which could lead to some subtle bugs. Instead when the
  # minimum version is 3.1 change this policy to NEW and remove
  # the hacks in place to work around it.
  cmake_policy(SET CMP0054 OLD)
endif()

if (POLICY CMP0042)
  # Enable `MACOSX_RPATH` by default.
  cmake_policy(SET CMP0042 NEW)
endif()

# This overrides the default flags for the different CMAKE_BUILD_TYPEs
set(CMAKE_USER_MAKE_RULES_OVERRIDE_C
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/c_flags_override.cmake")
set(CMAKE_USER_MAKE_RULES_OVERRIDE_CXX
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cxx_flags_override.cmake")
project(KLEE CXX C)

###############################################################################
# Project version
###############################################################################
set(KLEE_VERSION_MAJOR 0)
set(KLEE_VERSION_MINOR 1)
set(KLEE_VERSION_PATCH 0)
set(KLEE_VERSION_TWEAK 0)
set(KLEE_VERSION "${KLEE_VERSION_MAJOR}.${KLEE_VERSION_MINOR}.${KLEE_VERSION_PATCH}.${KLEE_VERSION_TWEAK}")
message(STATUS "KLEE version ${KLEE_VERSION}")
set(PACKAGE_STRING "\"KLEE ${KLEE_VERSION}\"")
set(PACKAGE_URL "\"https://klee.github.io\"")

################################################################################
# Set various useful variables depending on CMake version
################################################################################
if (("${CMAKE_VERSION}" VERSION_EQUAL "3.2") OR ("${CMAKE_VERSION}" VERSION_GREATER "3.2"))
  # In CMake >= 3.2 add_custom_command() supports a ``USES_TERMINAL`` argument
  set(ADD_CUSTOM_COMMAND_USES_TERMINAL_ARG "USES_TERMINAL")
else()
  set(ADD_CUSTOM_COMMAND_USES_TERMINAL_ARG "")
endif()

################################################################################
# Sanity check - Disallow building in source.
# Otherwise we would overwrite the Makefiles of the old build system.
################################################################################
if ("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
  message(FATAL_ERROR "In source builds are not allowed. You should invoke "
          "CMake from a different directory.")
endif()

################################################################################
# Build type
################################################################################
message(STATUS "CMake generator: ${CMAKE_GENERATOR}")
if (DEFINED CMAKE_CONFIGURATION_TYPES)
  # Multi-configuration build (e.g. Xcode). Here
  # CMAKE_BUILD_TYPE doesn't matter
  message(STATUS "Available configurations: ${CMAKE_CONFIGURATION_TYPES}")
else()
  # Single configuration generator (e.g. Unix Makefiles, Ninja)
  set(available_build_types Debug Release RelWithDebInfo MinSizeRel)
  if(NOT CMAKE_BUILD_TYPE)
    message(STATUS "CMAKE_BUILD_TYPE is not set. Setting default")
    message(STATUS "The available build types are: ${available_build_types}")
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE String
        "Options are ${available_build_types}"
        FORCE)
    # Provide drop down menu options in cmake-gui
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS ${available_build_types})
  endif()
  message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

  # Check the selected build type is valid
  list(FIND available_build_types "${CMAKE_BUILD_TYPE}" _build_type_index)
  if ("${_build_type_index}" EQUAL "-1")
    message(FATAL_ERROR "\"${CMAKE_BUILD_TYPE}\" is an invalid build type.\n"
      "Use one of the following build types ${available_build_types}")
  endif()
endif()


################################################################################
# Add our CMake module directory to the list of module search directories
################################################################################
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

################################################################################
# Assertions
################################################################################
option(ENABLE_KLEE_ASSERTS "Enable KLEE assertions" ON)
if (ENABLE_KLEE_ASSERTS)
  message(STATUS "KLEE assertions enabled")
  # Assume that -DNDEBUG isn't set.
else()
  message(STATUS "KLEE assertions disabled")
  list(APPEND KLEE_COMPONENT_CXX_DEFINES "NDEBUG")
endif()

################################################################################
# KLEE timestamps
################################################################################
option(KLEE_ENABLE_TIMESTAMP "Add timestamps to KLEE sources" OFF)

################################################################################
# Include useful CMake functions
################################################################################
include(GNUInstallDirs)
include(CheckIncludeFile)
include(CheckIncludeFileCXX)
include(CheckFunctionExists)
include(CheckPrototypeDefinition)
include("${CMAKE_SOURCE_DIR}/cmake/string_to_list.cmake")
include("${CMAKE_SOURCE_DIR}/cmake/klee_component_add_cxx_flag.cmake")
include("${CMAKE_SOURCE_DIR}/cmake/add_global_flag.cmake")

################################################################################
# Compiler flags for KLEE components
# Subsequent commands will append to these. These are used instead of
# directly modifying CMAKE_CXX_FLAGS so that other code can be easily built with
# different flags.
################################################################################
set(KLEE_COMPONENT_EXTRA_INCLUDE_DIRS "")
set(KLEE_COMPONENT_CXX_DEFINES "")
set(KLEE_COMPONENT_CXX_FLAGS "")
set(KLEE_SOLVER_LIBRARIES "")
set(KLEE_COMPONENT_EXTRA_LIBRARIES "")

################################################################################
# Find LLVM
################################################################################
include(${CMAKE_SOURCE_DIR}/cmake/find_llvm.cmake)
set(NEEDED_LLVM_VARS
  LLVM_PACKAGE_VERSION
  LLVM_VERSION_MAJOR
  LLVM_VERSION_MINOR
  LLVM_VERSION_PATCH
  LLVM_DEFINITIONS
  LLVM_ENABLE_ASSERTIONS
  LLVM_ENABLE_EH
  LLVM_ENABLE_RTTI
  LLVM_INCLUDE_DIRS
  LLVM_LIBRARY_DIRS
  LLVM_TOOLS_BINARY_DIR
  TARGET_TRIPLE
)

foreach (vname ${NEEDED_LLVM_VARS})
  message(STATUS "${vname}: \"${${vname}}\"")
  if (NOT (DEFINED "${vname}"))
    message(FATAL_ERROR "${vname} was not defined")
  endif()
endforeach()

if (LLVM_ENABLE_ASSERTIONS)
  # Certain LLVM debugging macros only work when LLVM was built with asserts
  set(ENABLE_KLEE_DEBUG 1) # for config.h
else()
  unset(ENABLE_KLEE_DEBUG) # for config.h
endif()


list(APPEND KLEE_COMPONENT_CXX_DEFINES ${LLVM_DEFINITIONS})
list(APPEND KLEE_COMPONENT_EXTRA_INCLUDE_DIRS ${LLVM_INCLUDE_DIRS})

# Find llvm-link
set(LLVM_LINK "${LLVM_TOOLS_BINARY_DIR}/llvm-link")
if (NOT EXISTS "${LLVM_LINK}")
  message(FATAL_ERROR "Failed to find llvm-link at \"${LLVM_LINK}\"")
endif()

# Find llvm-ar
set(LLVM_AR "${LLVM_TOOLS_BINARY_DIR}/llvm-ar")
if (NOT EXISTS "${LLVM_AR}")
  message(FATAL_ERROR "Failed to find llvm-ar at \"${LLVM_AR}\"")
endif()

# Find llvm-as
set(LLVM_AS "${LLVM_TOOLS_BINARY_DIR}/llvm-as")
if (NOT EXISTS "${LLVM_AS}")
  message(FATAL_ERROR "Failed to find llvm-as at \"${LLVM_AS}\"")
endif()

################################################################################
# C++ version
################################################################################
option(USE_CXX11 "Use C++11" OFF)
if ("${LLVM_PACKAGE_VERSION}" VERSION_GREATER "3.5.0")
  message(STATUS "Using LLVM >= 3.5.0. Forcing using C++11")
  set(USE_CXX11 ON CACHE BOOL "Use C++11" FORCE)
endif()

if (USE_CXX11)
  message(STATUS "Enabling C++11")
  # FIXME: Use CMake's own mechanism for managing C++ version.
  # Set globally because it is unlikely we would want to compile
  # using mixed C++ versions.
  add_global_cxx_flag("-std=c++11" REQUIRED)
else()
  # This is needed because with GCC 6 the default changed from gnu++98 to
  # gnu++14.
  add_global_cxx_flag("-std=gnu++98" REQUIRED)
endif()

################################################################################
# Warnings
################################################################################
include(${CMAKE_SOURCE_DIR}/cmake/compiler_warnings.cmake)

################################################################################
# Solvers
################################################################################

# Z3
option(ENABLE_SOLVER_Z3 "Enable Z3 solver support" OFF)
if (ENABLE_SOLVER_Z3)
  message(STATUS "Z3 solver support enabled")
  find_package(Z3)
  if (Z3_FOUND)
    message(STATUS "Found Z3")
    set(ENABLE_Z3 1) # For config.h
    list(APPEND KLEE_COMPONENT_EXTRA_INCLUDE_DIRS ${Z3_INCLUDE_DIRS})
    list(APPEND KLEE_SOLVER_LIBRARIES ${Z3_LIBRARIES})

    # Check the signature of `Z3_get_error_msg()`
    set (_old_CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES}")
    set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES} ${Z3_LIBRARIES})
    check_prototype_definition(Z3_get_error_msg
      "Z3_string Z3_get_error_msg(Z3_context c, Z3_error_code err)"
      "NULL" "${Z3_INCLUDE_DIRS}/z3.h" HAVE_Z3_GET_ERROR_MSG_NEEDS_CONTEXT)
    set(CMAKE_REQUIRED_LIBRARIES ${_old_CMAKE_REQUIRED_LIBRARIES})
    if (HAVE_Z3_GET_ERROR_MSG_NEEDS_CONTEXT)
      message(STATUS "Z3_get_error_msg requires context")
    else()
      message(STATUS "Z3_get_error_msg does not require context")
    endif()
  else()
    message(FATAL_ERROR "Z3 not found.")
  endif()
else()
  message(STATUS "Z3 solver support disabled")
  set(ENABLE_Z3 0) # For config.h
endif()

###############################################################################
# Exception handling
###############################################################################
if (NOT LLVM_ENABLE_EH)
  klee_component_add_cxx_flag("-fno-exceptions" REQUIRED)
endif()


################################################################################
# Generate `config.h`
################################################################################
configure_file(${CMAKE_SOURCE_DIR}/include/klee/Config/config.h.cmin
  ${CMAKE_BINARY_DIR}/include/klee/Config/config.h)

################################################################################
# Generate `CompileTimeInfo.h`
################################################################################
if (EXISTS "${CMAKE_SOURCE_DIR}/.git")
  # Get information from git. We use third-party code to do this. The nice
  # thing about this code is it will trigger a re-configure if the HEAD changes
  # which means when we build KLEE, it should always have the correct git
  # information.
  include(${CMAKE_SOURCE_DIR}/cmake/GetGitRevisionDescription.cmake)
  get_git_head_revision(_NOT_USED_KLEE_GIT_REFSPEC KLEE_GIT_SHA1HASH)
  message(STATUS "KLEE_GIT_SHA1HASH: ${KLEE_GIT_SHA1HASH}")
  git_describe(KLEE_GIT_TAG "--tags")
  message(STATUS "KLEE_GIT_TAG: ${KLEE_GIT_TAG}")
else()
  set(KLEE_GIT_SHA1HASH "unknown")
  set(KLEE_GIT_TAG "unknown")
endif()
set(AUTO_GEN_MSG "AUTOMATICALLY GENERATED. DO NOT EDIT!")
configure_file(${CMAKE_SOURCE_DIR}/include/klee/Config/CompileTimeInfo.h.cmin
  ${CMAKE_BINARY_DIR}/include/klee/Config/CompileTimeInfo.h
)

################################################################################
# Global include directories
################################################################################
include_directories("${CMAKE_SOURCE_DIR}/include")
include_directories("${CMAKE_BINARY_DIR}/include")

# Required for S2E
file(COPY "${CMAKE_SOURCE_DIR}/include" DESTINATION "${CMAKE_BINARY_DIR}")

################################################################################
# Set default location for targets in the build directory
################################################################################
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

################################################################################
# Report the value of various variables to aid debugging
################################################################################
message(STATUS "KLEE_COMPONENT_EXTRA_INCLUDE_DIRS: '${KLEE_COMPONENT_EXTRA_INCLUDE_DIRS}'")
message(STATUS "KLEE_COMPONENT_CXX_DEFINES: '${KLEE_COMPONENT_CXX_DEFINES}'")
message(STATUS "KLEE_COMPONENT_CXX_FLAGS: '${KLEE_COMPONENT_CXX_FLAGS}'")
message(STATUS "KLEE_COMPONENT_EXTRA_LIBRARIES: '${KLEE_COMPONENT_EXTRA_LIBRARIES}'")

################################################################################
# KLEE components
################################################################################
include("${CMAKE_SOURCE_DIR}/cmake/klee_add_component.cmake")
add_subdirectory(lib)

################################################################################
# Testing
################################################################################
option(ENABLE_UNIT_TESTS "Enable unittests" ON)

if (ENABLE_UNIT_TESTS)
    # Find lit
      set(LIT_TOOL_NAMES "llvm-lit" "lit")
      find_program(
        LIT_TOOL
        NAMES ${LIT_TOOL_NAMES}
        HINTS "${LLVM_TOOLS_BINARY_DIR}"
        DOC "Path to lit tool"
      )

      set(LIT_ARGS
        "-v;-s"
        CACHE
        STRING
        "Lit arguments"
    )

    # Add global test target
      add_custom_target(check
        COMMENT "Running tests"
    )

  message(STATUS "Unit tests enabled")
  add_subdirectory(unittests)
  add_dependencies(check unittests)
else()
  message(STATUS "Unit tests disabled")
endif()

################################################################################
# Miscellaneous install
################################################################################
install(FILES include/klee/klee.h DESTINATION include/klee)
install(DIRECTORY include DESTINATION include)
