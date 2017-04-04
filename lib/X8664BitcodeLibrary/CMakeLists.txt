# Copyright (C) 2017, Dependable Systems Laboratory, EPFL
# Copyright (C) 2017, Cyberhaven
# All rights reserved.
#
# Licensed under the Cyberhaven Research License Agreement.

include(LLVMBitcode)

set(FLAGS -D_GNU_SOURCE -DNEED_CPU_H -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
          -DCONFIG_SOFTMMU
          -DCONFIG_SYMBEX -DSYMBEX_LLVM_LIB -DSTATIC_TRANSLATOR -m64 -w -Wundef
          -Wredundant-decls -Wendif-labels -Wwrite-strings -fno-strict-aliasing
          -Wno-sign-compare -Wno-missing-field-initializers -O3)

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
