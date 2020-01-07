# Copyright (c) 2017 Dependable Systems Laboratory, EPFL
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

add_definitions(-D__STDC_FORMAT_MACROS -D_GNU_SOURCE -DNEED_CPU_H
                -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DSTATIC_TRANSLATOR
                -DTARGET_PHYS_ADDR_BITS=64 -DCONFIG_SYMBEX -DCONFIG_SOFTMMU -DCPU_TEMP_BUF_NLONGS=128
                -DTARGET_LONG_BITS=64 -DTARGET_INSN_START_EXTRA_WORDS=1)

add_library(X8664Translator STATIC ${LIBCPU_SRC_DIR}/src/target-${LIBCPU_TARGET}/translate.c
                                   ${LIBCPU_SRC_DIR}/src/target-${LIBCPU_TARGET}/helper.c
                                   ${LIBCPU_SRC_DIR}/src/target-${LIBCPU_TARGET}/op_helper.c
                                   ${LIBCPU_SRC_DIR}/src/fpu/softfloat.c
                                   ${LIBTCG_SRC_DIR}/src/tcg.c
                                   ${LIBTCG_SRC_DIR}/src/tcg-op.c
                                   ${LIBTCG_SRC_DIR}/src/tcg-common.c
                                   ${LIBTCG_SRC_DIR}/src/optimize.c
                                   ${LIBTCG_SRC_DIR}/src/tcg-llvm.cpp
                                   ${LIBTCG_SRC_DIR}/src/tcg-op-gvec.c
                                   ${LIBTCG_SRC_DIR}/src/tcg-op-vec.c
                                   ${LIBTCG_SRC_DIR}/src/tcg-runtime-gvec.c
                                   ${LIBTCG_SRC_DIR}/src/tcg-runtime.c
                                   ${LIBTCG_SRC_DIR}/src/cutils.c
                                   ${LIBCPU_SRC_DIR}/src/translate-all.c
                                   ${LIBCPU_SRC_DIR}/src/precise-pc.c
                                   Translator.cpp
                                   TranslatorWrapper.cpp)

target_include_directories(X8664Translator PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                                                   ${GLIB2_INCLUDE_DIRS}
                                                   ${LIBCPU_SRC_DIR}/src
                                                   ${LIBCPU_SRC_DIR}/src/target-${LIBCPU_TARGET}
                                                   ${LIBCPU_SRC_DIR}/include/fpu
                                                   ${LIBCPU_SRC_DIR}/include
                                                   ${LIBTCG_SRC_DIR}/include
                                                   ${LIBTCG_SRC_DIR}/src
                                                   ${LIBTCG_SRC_DIR}/src/${LIBCPU_TARGET})

target_compile_options(X8664Translator PRIVATE -Wredundant-decls -w -Wundef
                       -Wendif-labels -Wwrite-strings -fno-strict-aliasing
                       -Wno-sign-compare -Wno-missing-field-initializers
                       -fexceptions)
