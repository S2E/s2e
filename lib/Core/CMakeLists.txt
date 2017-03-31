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
	ExecutorTimers.cpp
	ExecutorUtil.cpp
	ExternalDispatcher.cpp
	ImpliedValue.cpp
	Memory.cpp
	MemoryManager.cpp
	PTree.cpp
	Searcher.cpp
	SolverFactory.cpp
	SpecialFunctionHandler.cpp
	StatsTracker.cpp
	TimingSolver.cpp
	UserSearcher.cpp
)
