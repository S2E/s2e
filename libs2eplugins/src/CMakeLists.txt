# Copyright (C) 2017-2019, Cyberhaven
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

PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS ${CMAKE_CURRENT_SOURCE_DIR}/s2e/Plugins/ExecutionTracers/TraceEntries.proto)

add_library(
    s2eplugins

    # Core plugins
    s2e/Plugins/Core/BaseInstructions.cpp
    s2e/Plugins/Core/HostFiles.cpp
    s2e/Plugins/Core/Vmi.cpp
    s2e/Plugins/Core/StatsTracker.cpp

    # Support plugins
    s2e/Plugins/Support/KeyValueStore.cpp
    s2e/Plugins/Support/WebServiceInterface.cpp
    s2e/Plugins/Support/Screenshot.cpp

    # OS support
    s2e/Plugins/OSMonitors/ModuleDescriptor.cpp

    # Windows guests support
    s2e/Plugins/OSMonitors/Windows/BlueScreenInterceptor.cpp
    s2e/Plugins/OSMonitors/Windows/WindowsCrashDumpGenerator.cpp
    s2e/Plugins/OSMonitors/Windows/WindowsMonitor.cpp
    s2e/Plugins/OSMonitors/Windows/WindowsCrashMonitor.cpp

    # Linux guests support
    s2e/Plugins/OSMonitors/Linux/BaseLinuxMonitor.cpp
    s2e/Plugins/OSMonitors/Linux/LinuxMonitor.cpp
    s2e/Plugins/OSMonitors/Linux/DecreeMonitor.cpp
    s2e/Plugins/OSMonitors/Raw/RawMonitor.cpp

    # Guest support
    s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.cpp
    s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.cpp
    s2e/Plugins/OSMonitors/Support/ThreadExecutionDetector.cpp
    s2e/Plugins/OSMonitors/Support/ModuleMap.cpp
    s2e/Plugins/OSMonitors/Support/MemoryMap.cpp
    s2e/Plugins/OSMonitors/Support/MemUtils.cpp
    s2e/Plugins/OSMonitors/Support/GuestCodeHooking.cpp
    s2e/Plugins/OSMonitors/Support/ITracker.cpp
    s2e/Plugins/OSMonitors/OSMonitor.cpp

    # CGC support
    s2e/Plugins/VulnerabilityAnalysis/CGCInterface.cpp
    s2e/Plugins/VulnerabilityAnalysis/PovGenerator.cpp
    s2e/Plugins/VulnerabilityAnalysis/FilePovGenerator.cpp
    s2e/Plugins/VulnerabilityAnalysis/DecreePovGenerator.cpp
    s2e/Plugins/VulnerabilityAnalysis/PovGenerationPolicy.cpp
    s2e/Plugins/VulnerabilityAnalysis/Recipe/Recipe.cpp
    s2e/Plugins/VulnerabilityAnalysis/Recipe/RecipeDescriptor.cpp
    s2e/Plugins/VulnerabilityAnalysis/Recipe/Register.cpp

    # Tracing plugins
    s2e/Plugins/ExecutionTracers/ExecutionTracer.cpp
    s2e/Plugins/ExecutionTracers/UserSpaceTracer.cpp
    s2e/Plugins/ExecutionTracers/ModuleTracer.cpp
    s2e/Plugins/ExecutionTracers/EventTracer.cpp
    s2e/Plugins/ExecutionTracers/TestCaseGenerator.cpp
    s2e/Plugins/ExecutionTracers/MemoryTracer.cpp
    s2e/Plugins/ExecutionTracers/InstructionCounter.cpp
    s2e/Plugins/ExecutionTracers/TranslationBlockTracer.cpp
    s2e/Plugins/ExecutionTracers/ExceptionTracer.cpp
    s2e/Plugins/ExecutionTracers/StateSwitchTracer.cpp
    s2e/Plugins/ExecutionTracers/TBCoverageTracer.cpp

    # Symbolic hardware
    s2e/Plugins/SymbolicHardware/SymbolicHardware.cpp

    # Searchers
    s2e/Plugins/Searchers/MultiSearcher.cpp
    s2e/Plugins/Searchers/CooperativeSearcher.cpp
    s2e/Plugins/Searchers/MergingSearcher.cpp
    s2e/Plugins/Searchers/LoopExitSearcher.cpp
    s2e/Plugins/Searchers/CUPASearcher.cpp
    s2e/Plugins/Searchers/SeedSearcher.cpp
    s2e/Plugins/Searchers/SeedScheduler.cpp

    # Function models
    s2e/Plugins/Models/BaseFunctionModels.cpp
    s2e/Plugins/Models/FunctionModels.cpp
    s2e/Plugins/Models/CRC.cpp
    s2e/Plugins/Models/StaticFunctionModels.cpp

    # Static analysis
    s2e/Plugins/StaticAnalysis/ControlFlowGraph.cpp
    s2e/Plugins/StaticAnalysis/LoopDetector.cpp
    s2e/Plugins/StaticAnalysis/EdgeDetector.cpp

    # Path limiters
    s2e/Plugins/PathLimiters/EdgeKiller.cpp
    s2e/Plugins/PathLimiters/ResourceMonitor.cpp
    s2e/Plugins/PathLimiters/ForkLimiter.cpp

    # Code coverage
    s2e/Plugins/Coverage/BasicBlockCoverage.cpp
    s2e/Plugins/Coverage/TranslationBlockCoverage.cpp
    s2e/Plugins/Coverage/EdgeCoverage.cpp

    # Misc plugins
    s2e/Plugins/Example.cpp

    # Analysis plugins
    s2e/Plugins/Analyzers/CacheSim.cpp
    s2e/Plugins/Analyzers/AddressTracker.cpp
    s2e/Plugins/Analyzers/CFIChecker.cpp
    s2e/Plugins/Analyzers/Tickler.cpp


    # Execution monitors
    s2e/Plugins/ExecutionMonitors/CallSiteMonitor.cpp
    s2e/Plugins/ExecutionMonitors/FunctionMonitor.cpp
    s2e/Plugins/ExecutionMonitors/StackMonitor.cpp
    s2e/Plugins/ExecutionMonitors/StackClustering.cpp
    s2e/Plugins/ExecutionMonitors/LibraryCallMonitor.cpp

    # Lua bindings
    s2e/Plugins/Lua/LuaBindings.cpp
    s2e/Plugins/Lua/LuaModuleDescriptor.cpp
    s2e/Plugins/Lua/LuaS2EExecutionState.cpp
    s2e/Plugins/Lua/LuaS2EExecutionStateMemory.cpp
    s2e/Plugins/Lua/LuaS2EExecutionStateRegisters.cpp
    s2e/Plugins/Lua/LuaS2E.cpp
    s2e/Plugins/Lua/LuaFunctionInstrumentation.cpp
    s2e/Plugins/Lua/LuaInstructionInstrumentation.cpp
    s2e/Plugins/Lua/LuaInstrumentationState.cpp
    s2e/Plugins/Lua/LuaInstructionInstrumentationState.cpp
    s2e/Plugins/Lua/LuaFunctionInstrumentationState.cpp
    s2e/Plugins/Lua/LuaExpression.cpp
    s2e/Plugins/Lua/LuaCoreEvents.cpp

    ${PROTO_SRCS} ${PROTO_HDRS}
)


target_include_directories (s2eplugins PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})


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
set(COMMON_FLAGS "${COMMON_FLAGS} -DLIBS2E_PLUGINS")
set(COMMON_FLAGS "${COMMON_FLAGS} -Wall -fPIC -fno-strict-aliasing -fexceptions -std=c++17")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${WERROR_FLAGS} ${COMMON_FLAGS}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${WERROR_FLAGS} ${COMMON_FLAGS}")
