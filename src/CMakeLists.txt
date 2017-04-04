# Copyright (C) 2017, Cyberhaven
# All rights reserved.
#
# Licensed under the Cyberhaven Research License Agreement.

add_library(
    s2ecore
    S2E.cpp
    S2EExecutionState.cpp
    S2EExecutionStateRegisters.cpp
    S2EExecutor.cpp
    S2EExecutionStateMemory.cpp
    S2EExecutionStateTlb.cpp
    S2EDeviceState.cpp
    AddressSpaceCache.cpp
    MMUFunctionHandlers.cpp

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
)

target_include_directories (s2ecore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

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
set(COMMON_FLAGS "${COMMON_FLAGS} -Wall -fPIC -fno-strict-aliasing -fexceptions -std=c++11")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${WERROR_FLAGS} ${COMMON_FLAGS}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${WERROR_FLAGS} ${COMMON_FLAGS}")
