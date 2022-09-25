#===------------------------------------------------------------------------===#
#
#                     The KLEE Symbolic Virtual Machine
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#
klee_add_component(kleeCore
	AddressSpace.cpp
	Common.cpp
	Context.cpp
	CoreStats.cpp
	ExecutionState.cpp
	Executor.cpp
	ExternalDispatcher.cpp
	Memory.cpp
	Searcher.cpp
	SpecialFunctionHandler.cpp
)

set(LLVM_COMPONENTS
  core
  support
)

# list(APPEND LLVM_COMPONENTS engine)

klee_get_llvm_libs(LLVM_LIBS ${LLVM_COMPONENTS})
target_link_libraries(kleeCore PUBLIC ${LLVM_LIBS})
