# Copyright (C) 2017, Dependable Systems Laboratory, EPFL
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

include(LLVMBitcode)

set(FLAGS -D_GNU_SOURCE -DNEED_CPU_H -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
          -DCONFIG_SOFTMMU
          -DCONFIG_SYMBEX -DSYMBEX_LLVM_LIB -DSTATIC_TRANSLATOR -m64 -w -Wundef
          -Wredundant-decls -Wendif-labels -Wwrite-strings -fno-strict-aliasing
          -Wno-sign-compare -Wno-missing-field-initializers -O3 -DTARGET_INSN_START_EXTRA_WORDS=1)

get_property(INC_DIRS DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY INCLUDE_DIRECTORIES)

set(INC_DIRS ${INC_DIRS}
             ${CMAKE_CURRENT_SOURCE_DIR}
             ${GLIB2_INCLUDE_DIRS}
             ${LIBQ_INCLUDE_DIR}
             ${LIBCPU_SRC_DIR}/include
             ${LIBCPU_SRC_DIR}/src
             ${LIBCPU_SRC_DIR}/src/target-${LIBCPU_TARGET}
             ${LIBCPU_SRC_DIR}/include/fpu
             ${LIBTCG_SRC_DIR}/include
             ${LIBTCG_SRC_DIR}/include/${LIBCPU_TARGET})

link_llvm_bitcode(X8664BitcodeLibrary.bc "${FLAGS}" "${INC_DIRS}"
                                         ${LIBCPU_SRC_DIR}/src/target-${LIBCPU_TARGET}/op_helper.c
                                         ${LIBCPU_SRC_DIR}/src/fpu/softfloat.c
                                         ${CMAKE_CURRENT_SOURCE_DIR}/../X86BitcodeLibrary/BitcodeLibrary.cpp)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/X8664BitcodeLibrary.bc DESTINATION lib)
