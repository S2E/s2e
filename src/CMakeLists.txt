# Copyright (C) 2017, Cyberhaven
# All rights reserved.
#
# Licensed under the Cyberhaven Research License Agreement.

add_library(
    s2e SHARED
    libs2e.c
    s2e-kvm-interface.c
    s2e-kvm-io.c
    s2e-kvm-libcpu-stubs.c
    s2e-kvm-state.c
    s2e-kvm-trace.c
    s2e-libcpu-interface.c
    crashdump.cpp
)

add_executable(
    tests2e
    test.c
)

# Specify whole path for libraries so that libs2e can be relinked if any of them changes.
# Just specifying the short library name prevents cmake from detecting the dependency.
if(WITH_TARGET MATCHES "s2e")
set(LIBS -Wl,--whole-archive ${LIBS2EPLUGINS_LIBRARY_DIR}/libs2eplugins.a ${LIBS2ECORE_LIBRARY_DIR}/libs2ecore.a -Wl,--no-whole-archive ${LIBS})
endif()

set(LIBS ${LIBS} ${LIBCPU_LIBRARY_DIR}/libcpu.a ${LIBTCG_LIBRARY_DIR}/libtcg.a)

if(WITH_TARGET MATCHES "s2e")
    set(LIBS ${LIBS} ${KLEE_DIR}/lib/libkleeCore.a
                     ${KLEE_DIR}/lib/libkleeModule.a
                     ${KLEE_DIR}/lib/libkleaverSolver.a
                     ${KLEE_DIR}/lib/libkleaverExpr.a
                     ${KLEE_DIR}/lib/libkleeSupport.a
                     ${KLEE_DIR}/lib/libkleeBasic.a)
    set(LIBS ${LIBS} ${VMI_LIBRARY_DIR}/libvmi.a
                     elf)
    set(LIBS ${LIBS} memcached
                     lua
                     ${LLVM_LIBS}
                     z3
                     ${FSIGCXX_LIBRARY_DIR}/libfsigc++.a
                     ${LIBQ_LIBRARY_DIR}/libq.a
                     ${PROTOBUF_LIBRARIES})
    set(LIBS ${LIBS} boost_serialization
                     boost_system
                     boost_regex)
endif()

set(LIBS ${LIBS} ${LIBCOROUTINE_LIBRARY_DIR}/libcoroutine.a  ${CAPSTONE_LIB_DIR}/libcapstone.a pthread glib-2.0 bsd)

target_link_libraries(tests2e PUBLIC ${LIBCOROUTINE_LIBRARY_DIR}/libcoroutine.a pthread glib-2.0)
target_link_libraries(s2e ${LIBS})


set(WERROR_FLAGS "-Werror -Wno-zero-length-array -Wno-c99-extensions          \
                  -Wno-gnu-anonymous-struct -Wno-nested-anon-types            \
                  -Wno-extended-offsetof -Wno-gnu-statement-expression        \
                  -Wno-gnu-zero-variadic-macro-arguments -Wno-vla-extension   \
                  -Wno-covered-switch-default -Wno-shift-negative-value       \
                  -Wno-deprecated-register -Wno-sign-compare                  \
                  -Wno-missing-field-initializers -Wno-mismatched-tags        \
                  -Wno-deprecated-declarations -Wno-initializer-overrides     \
                  -Wno-zero-length-array")

set(COMMON_FLAGS "-D__STDC_FORMAT_MACROS -D_GNU_SOURCE -DNEED_CPU_H  -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DTARGET_PHYS_ADDR_BITS=64")
set(COMMON_FLAGS "${COMMON_FLAGS} -Wall -fPIC -fno-strict-aliasing -fexceptions")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${WERROR_FLAGS} ${COMMON_FLAGS} -std=c++11")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${WERROR_FLAGS} ${COMMON_FLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/mapfile")
