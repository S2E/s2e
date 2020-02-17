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
    s2ecore
    S2E.cpp
    S2EExecutionState.cpp
    S2EExecutionStateRegisters.cpp
    S2EExecutor.cpp
    S2EExecutionStateMemory.cpp
    S2EExecutionStateTlb.cpp
    S2EDeviceState.cpp
    S2EExternalDispatcher.cpp
    S2ETranslationBlock.cpp
    AddressSpaceCache.cpp
    MMUFunctionHandlers.cpp
    FunctionHandlers.cpp

    PluginManager.cpp
    Plugin.cpp
    CorePluginInterface.cpp
    CorePlugin.cpp
    ConfigFile.cpp

    s2e-qmp.cpp
    SymbolicHardwareHook.cpp
    ExprInterface.cpp
    S2EStatsTracker.cpp
    Synchronization.cpp
    Utils.cpp
    MemoryDebugger.cpp
)

target_include_directories (s2ecore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

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
set(COMMON_FLAGS "${COMMON_FLAGS} -Wall -fPIC -fno-strict-aliasing -fexceptions -std=c++11")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${WERROR_FLAGS} ${COMMON_FLAGS}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${WERROR_FLAGS} ${COMMON_FLAGS}")
