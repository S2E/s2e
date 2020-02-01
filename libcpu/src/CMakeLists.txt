# Copyright 2016 - Cyberhaven
# This work is licensed under the terms of the GNU LGPL, version 2.1 or later.

add_library(
    cpu cpu-exec.c cpus.c exec.c exec-bp.c exec-log.c exec-memdbg.c exec-phys.c exec-phystb.c exec-ram.c exec-tb.c exec-tlb.c ioport.c memory.c timer.c translate-all.c
    fpu/softfloat.c precise-pc.c
    target-i386/cpuid.c target-i386/helper.c target-i386/op_helper.c target-i386/translate.c disas.c
)


target_include_directories (cpu PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/target-i386
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/fpu
    ${CMAKE_BINARY_DIR}/include
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__STDC_FORMAT_MACROS -D_GNU_SOURCE -DNEED_CPU_H  -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DTARGET_PHYS_ADDR_BITS=64")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fPIC -Werror -fno-omit-frame-pointer")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-strict-aliasing -Wno-sign-compare -Wno-missing-field-initializers -Wno-mismatched-tags -Wno-deprecated-declarations -Wno-initializer-overrides -Wno-zero-length-array")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fexceptions")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fPIC -Wno-mismatched-tags -Werror -Wno-zero-length-array")


if (WITH_SYMBEX)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCONFIG_SYMBEX")

set(CARGS_LIST "${CMAKE_C_FLAGS}")
separate_arguments(CARGS_LIST)

get_property(dirs TARGET cpu PROPERTY INCLUDE_DIRECTORIES)
foreach(dir ${dirs})
  message(STATUS "dir='${dir}'")
  set(BC_INC_DIRS "${BC_INC_DIRS} -I${dir}")
endforeach()
separate_arguments(BC_INC_DIRS)

get_filename_component(LLVM_BIN_DIR ${CMAKE_C_COMPILER} DIRECTORY)

add_custom_target(
    op_helper_bc ALL
    ${CMAKE_C_COMPILER} ${CMAKE_CURRENT_SOURCE_DIR}/target-i386/op_helper.c -c ${CARGS_LIST} -Wno-unused-function -O3 -DSYMBEX_LLVM_LIB -march=x86-64 -emit-llvm -o ${CMAKE_CURRENT_BINARY_DIR}/op_helper-org.bc ${BC_INC_DIRS}
    COMMAND ${CMAKE_C_COMPILER} ${CMAKE_CURRENT_SOURCE_DIR}/fpu/softfloat.c -c ${CARGS_LIST} -Wno-unused-function -O3 -DSYMBEX_LLVM_LIB -march=x86-64 -emit-llvm -o ${CMAKE_CURRENT_BINARY_DIR}/softfloat.bc ${BC_INC_DIRS}
    COMMAND ${LLVM_BIN_DIR}/llvm-link ${CMAKE_CURRENT_BINARY_DIR}/op_helper-org.bc ${CMAKE_CURRENT_BINARY_DIR}/softfloat.bc -o ${CMAKE_CURRENT_BINARY_DIR}/op_helper.bc
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/target-i386/op_helper.c ${CMAKE_CURRENT_SOURCE_DIR}/fpu/softfloat.c
)

endif (WITH_SYMBEX)

MESSAGE( STATUS "CMAKE_C_FLAGS: " ${CMAKE_C_FLAGS} )
MESSAGE( STATUS "CMAKE_C_FLAGS_RELEASE: " ${CMAKE_C_FLAGS_RELEASE} )
MESSAGE( STATUS "CMAKE_C_FLAGS_RELWITHDEBINFO: " ${CMAKE_C_FLAGS_RELWITHDEBINFO} )
MESSAGE( STATUS "WITH_SYMBEX: " ${WITH_SYMBEX} )
MESSAGE( STATUS "DIRS:" ${HOST_INCLUDE_DIR} ${TARGET_INCLUDE_DIR})
