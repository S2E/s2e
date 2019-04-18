# Copyright (c) 2016 Dependable Systems Laboratory, EPFL
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


###############################################################################
# Private functions
###############################################################################

# Ensure that the list of include directories is formatted correctly
function(_format_includes INCS)
  foreach(INC_DIR ${ARGN})
    if(${INC_DIR} MATCHES "^-I")
      list(APPEND _INCS ${INC_DIR})
    else()
      list(APPEND _INCS "-I${INC_DIR}")
    endif()
  endforeach()
  set(INCS ${_INCS} PARENT_SCOPE)
endfunction(_format_includes)

# Determine whether to use clang or clang++ (based on the file extension)
function(_get_compiler COMPILER SRC)
  get_filename_component(SRC_EXT ${SRC} EXT)

  if(SRC_EXT STREQUAL ".c")
    set(COMPILER ${LLVM_TOOLS_BINARY_DIR}/clang PARENT_SCOPE)
  elseif(SRC_EXT STREQUAL ".cpp" OR SRC_EXT STREQUAL ".cc")
    set(COMPILER ${LLVM_TOOLS_BINARY_DIR}/clang++ PARENT_SCOPE)
  else()
    message(FATAL_ERROR "Unknown file extension \"${SRC_EXT}\" for ${SRC} LLVM bitcode build")
  endif()
endfunction(_get_compiler)

# Determine language (C or CXX) (based on the file extension)
function(_get_language LANG SRC)
  get_filename_component(SRC_EXT ${SRC} EXT)

  if(SRC_EXT STREQUAL ".c")
    set(LANG C PARENT_SCOPE)
  elseif(SRC_EXT STREQUAL ".cpp" OR SRC_EXT STREQUAL ".cc")
    set(LANG CXX PARENT_SCOPE)
  else()
    message(FATAL_ERROR "Unknown file extension \"${SRC_EXT}\" for ${SRC} LLVM bitcode build")
  endif()
endfunction(_get_language)

###############################################################################
# Public functions
###############################################################################

#
# Compile a C/C++ source file into LLVM bitcode.
#
# @param OUTPUT An absolute path of the resulting bitcode file.
# @param FLAGS Compilation flags.
# @param INC_DIRS Include directories.
# @param SRC An absolute path to the C/C++ file to compile.
#
function(build_llvm_bitcode OUTPUT FLAGS INC_DIRS SRC)
  _get_compiler(COMPILER ${SRC})
  _get_language(LANG ${SRC})
  _format_includes(INCS ${INC_DIRS})
  get_filename_component(SRC_BASE ${SRC} NAME_WE)

  add_custom_command(OUTPUT ${OUTPUT}
                     COMMAND ${COMPILER} ${INCS}
                             -emit-llvm -c ${FLAGS}
                             -o ${OUTPUT}
                             ${SRC}
                     IMPLICIT_DEPENDS ${LANG} ${SRC}
                     DEPENDS ${SRC})

  add_custom_target(${SRC_BASE}.bc ALL DEPENDS ${OUTPUT})
endfunction(build_llvm_bitcode)

#
# Link multiple LLVM bitcode files into a single bitcode file.
#
# @param OUTPUT The absolute path of the resulting bitcode file.
# @param FLAGS Compilation flags
# @param INC_DIRS Include directories.
# @param SRC An absolute path to the first C/C++ file to link.
# @param ARGN A list of absolute paths to other C/C++ files to link.
#
function(link_llvm_bitcode OUTPUT FLAGS INC_DIRS SRC)
  set(LINK ${LLVM_TOOLS_BINARY_DIR}/llvm-link)
  list(APPEND INPUT_FILES ${SRC} ${ARGN})
  get_filename_component(OUTPUT_BASE ${OUTPUT} NAME_WE)

  # Build all the individual bitcode files
  foreach(INPUT_FILE ${INPUT_FILES})
    get_filename_component(SRC_BASE ${INPUT_FILE} NAME_WE)
    set(BC_FILE ${CMAKE_CURRENT_BINARY_DIR}/${SRC_BASE}.bc)

    _get_compiler(COMPILER ${INPUT_FILE})
    _get_language(LANG ${INPUT_FILE})
    _format_includes(INCS ${INC_DIRS})

    add_custom_command(OUTPUT ${BC_FILE}
                       COMMAND ${COMPILER} ${INCS}
                               -emit-llvm -c ${FLAGS}
                               -o ${BC_FILE}
                               ${INPUT_FILE}
                       IMPLICIT_DEPENDS ${LANG} ${INPUT_FILE}
                       DEPENDS ${INPUT_FILE})
    # No need to add a custom target for individual Bitcode files

    list(APPEND BC_FILES ${BC_FILE})
  endforeach()

  # Link the bitcode files
  add_custom_command(OUTPUT ${OUTPUT}
                     COMMAND ${LINK} -o ${OUTPUT} ${BC_FILES}
                     DEPENDS ${BC_FILES})
  add_custom_target(${OUTPUT_BASE} ALL DEPENDS ${OUTPUT})
endfunction(link_llvm_bitcode)

#
# Build an LLVM bitcode library.
#
# @param OUTPUT The absolute path of the resulting bitcode library.
# @param FLAGS Compilation flags.
# @param INC_DIRS Include directories.
# @param SRC An absolute path to a C/C++ file to archive.
# @param ARGN A list of absolute paths to other C/C++ files to include in the
# bitecode library.
#
function(build_llvm_bitcode_lib OUTPUT FLAGS INC_DIRS SRC)
  set(AR ${LLVM_TOOLS_BINARY_DIR}/llvm-ar)
  list(APPEND INPUT_FILES ${SRC} ${ARGN})
  get_filename_component(OUTPUT_BASE ${OUTPUT} NAME_WE)

  # Build all the individual bitcode files
  foreach(INPUT_FILE ${INPUT_FILES})
    get_filename_component(SRC_BASE ${INPUT_FILE} NAME_WE)
    set(BC_FILE ${CMAKE_CURRENT_BINARY_DIR}/${SRC_BASE}.bc)

    _get_compiler(COMPILER ${INPUT_FILE})
    _get_language(LANG ${INPUT_FILE})
    _format_includes(INCS ${INC_DIRS})

    add_custom_command(OUTPUT ${BC_FILE}
                       COMMAND ${COMPILER} ${INCS}
                               -emit-llvm -c ${FLAGS}
                               -o ${BC_FILE}
                               ${INPUT_FILE}
                       IMPLICIT_DEPENDS ${LANG} ${INPUT_FILE}
                       DEPENDS ${INPUT_FILE})
    # No need to add a custom target for individual Bitcode files

    list(APPEND BC_FILES ${BC_FILE})
  endforeach()

  # Build the bitcode library
  add_custom_command(OUTPUT ${OUTPUT}
                     COMMAND ${AR} rcs ${OUTPUT} ${BC_FILES}
                     DEPENDS ${BC_FILES})
  add_custom_target(${OUTPUT_BASE} ALL DEPENDS ${OUTPUT})
endfunction(build_llvm_bitcode_lib)

#
# Optimize an LLVM bitcode file with the LLVM optimizer.
#
# @param OUTPUT The absolute path of the resulting bitcode file.
# @param SRC The absolute path to the LLVM bitcode file to optimize.
# @param OPTIMIZATION An LLVM optimization to perform.
# @param ARGN A list of other optimizations to perform.
#
function(optimize_llvm_bitcode OUTPUT SRC OPTIMIZATION)
  set(OPTIMIZER ${LLVM_TOOLS_BINARY_DIR}/opt)
  list(APPEND OPTIMIZATIONS ${OPTIMIZATION} ${ARGN})
  get_filename_component(SRC_BASE ${SRC} NAME_WE)
  get_filename_component(OUTPUT_BASE ${OUTPUT} NAME_WE)

  # Ensure that the optimization flags are formatted correctly
  foreach(OPT ${OPTIMIZATIONS})
    if(${OPT} MATCHES "^-")
      list(APPEND OPTS ${OPT})
    else()
      list(APPEND OPTS "-${OPT}")
    endif()
  endforeach()

  # Run the optimizer
  add_custom_command(OUTPUT ${OUTPUT}
                     COMMAND ${OPTIMIZER} ${OPTS} ${SRC} > ${OUTPUT}
                     DEPENDS ${SRC})
  add_custom_target(${OUTPUT_BASE} ALL DEPENDS ${OUTPUT})
endfunction(optimize_llvm_bitcode)

###############################################################################

# Ensure that LLVM is available
find_package(LLVM REQUIRED)
