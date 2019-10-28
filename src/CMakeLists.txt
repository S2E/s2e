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

set (TCG_SOURCES)
list (APPEND TCG_SOURCES cutils.c tcg.c  tcg-common.c tcg-op.c optimize.c tcg-op-gvec.c tcg-runtime-gvec.c tcg-op-vec.c)

if (WITH_SYMBEX)
    list(APPEND TCG_SOURCES tcg-llvm.cpp)
endif (WITH_SYMBEX)

add_library(tcg ${TCG_SOURCES})

set (COMMON_FLAGS "-Wall -fPIC -Werror -Wno-zero-length-array -Wno-mismatched-tags -Wno-initializer-overrides")
set (COMMON_FLAGS "${COMMON_FLAGS} -DCONFIG_SOFTMMU -DCPU_TEMP_BUF_NLONGS=128")

if (WITH_SYMBEX)
    set (COMMON_FLAGS "${COMMON_FLAGS} -DCONFIG_SYMBEX -DTCG_ENABLE_MEM_TRACING")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
endif (WITH_SYMBEX)

if (WITH_SYMBEX_MP)
    set (COMMON_FLAGS "${COMMON_FLAGS} -DCONFIG_SYMBEX_MP")
endif (WITH_SYMBEX_MP)

if (TARGET_X86_64)
    set (COMMON_FLAGS "${COMMON_FLAGS} -DTARGET_X86_64")
endif (TARGET_X86_64)

if (TARGET_LONG_BITS)
    set (COMMON_FLAGS "${COMMON_FLAGS} -DTARGET_LONG_BITS=${TARGET_LONG_BITS}")
else (TARGET_LONG_BITS)
    MESSAGE (FATAL_ERROR "Please specify -DTARGET_LONG_BITS")
endif (TARGET_LONG_BITS)

if (TARGET_INSN_START_EXTRA_WORDS)
    set (COMMON_FLAGS "${COMMON_FLAGS} -DTARGET_INSN_START_EXTRA_WORDS=${TARGET_INSN_START_EXTRA_WORDS}")
else (TARGET_INSN_START_EXTRA_WORDS)
    MESSAGE (FATAL_ERROR "Please specify -DTARGET_INSN_START_EXTRA_WORDS")
endif (TARGET_INSN_START_EXTRA_WORDS)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMMON_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COMMON_FLAGS}")

MESSAGE( STATUS "CMAKE_C_FLAGS: " ${CMAKE_C_FLAGS} )
MESSAGE( STATUS "WITH_SYMBEX: " ${WITH_SYMBEX} )
MESSAGE( STATUS "WITH_SYMBEX_MP: " ${WITH_SYMBEX_MP} )
