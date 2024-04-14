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

add_library(
    s2e SHARED
    libs2e.cpp
    s2e-kvm-io.cpp
    s2e-kvm-state.cpp
    s2e-kvm-trace.cpp
    s2e-kvm.cpp
    s2e-kvm-vm.cpp
    s2e-kvm-vcpu.cpp
    s2e-libcpu-interface.cpp
    crashdump.cpp
)

add_executable(
    tests2e
    test.cpp
)

# Specify whole path for libraries so that libs2e can be relinked if any of them changes.
# Just specifying the short library name prevents cmake from detecting the dependency.
if(WITH_TARGET MATCHES "s2e")
set(LIBS -Wl,--whole-archive ${LIBS2EPLUGINS_LIBRARY_DIR}/libs2eplugins.a ${LIBS2ECORE_LIBRARY_DIR}/libs2ecore.a -Wl,--no-whole-archive ${LIBS})
endif()

set(LIBS ${LIBS} ${LIBCPU_LIBRARY_DIR}/libcpu.a ${LIBTCG_LIBRARY_DIR}/libtcg.a)

if(WITH_TARGET MATCHES "s2e")
    set(LIBS ${LIBS} ${KLEE_LIBRARY_DIR}/libkleeCore.a
                     ${KLEE_LIBRARY_DIR}/libkleeModule.a
                     ${KLEE_LIBRARY_DIR}/libkleaverSolver.a
                     ${KLEE_LIBRARY_DIR}/libkleaverExpr.a
                     ${KLEE_LIBRARY_DIR}/libkleeSupport.a
                     ${KLEE_LIBRARY_DIR}/libkleeBasic.a)
    set(LIBS ${LIBS} ${VMI_LIBRARY_DIR}/libvmi.a
                     elf)
    set(LIBS ${LIBS} memcached
                     lua
                     ${LLVM_LIBS}
                     z3.a
                     gomp
                     ${PROTOBUF_LIBRARIES})
    set(LIBS ${LIBS} boost_serialization
                     boost_system
                     boost_regex)
endif()

set(LIBS ${LIBS} ${LIBCOROUTINE_LIBRARY_DIR}/libcoroutine.a ${FSIGCXX_LIBRARY_DIR}/libfsigc++.a ${LIBQ_LIBRARY_DIR}/libq.a ${CAPSTONE_LIBRARIES} pthread glib-2.0 bsd dl)

target_link_libraries(tests2e PUBLIC ${LIBCOROUTINE_LIBRARY_DIR}/libcoroutine.a pthread glib-2.0)
target_link_libraries(s2e ${LIBS})


set(WERROR_FLAGS "-Werror -Wno-zero-length-array -Wno-c99-extensions          \
                  -Wno-gnu-anonymous-struct -Wno-nested-anon-types            \
                  -Wno-gnu-statement-expression                               \
                  -Wno-gnu-zero-variadic-macro-arguments -Wno-vla-extension   \
                  -Wno-covered-switch-default -Wno-shift-negative-value       \
                  -Wno-deprecated-register -Wno-sign-compare                  \
                  -Wno-missing-field-initializers -Wno-mismatched-tags        \
                  -Wno-deprecated-declarations -Wno-initializer-overrides     \
                  -Wno-zero-length-array")

set(COMMON_FLAGS "-D__STDC_FORMAT_MACROS -D_GNU_SOURCE -DNEED_CPU_H  -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DTARGET_PHYS_ADDR_BITS=64")
set(COMMON_FLAGS "${COMMON_FLAGS} -Wall -fPIC -fno-strict-aliasing -fexceptions")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${WERROR_FLAGS} ${COMMON_FLAGS} -std=c++14")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${WERROR_FLAGS} ${COMMON_FLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS "-Wl,--as-needed -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/mapfile")
