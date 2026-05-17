#===------------------------------------------------------------------------===#
#
#                     The KLEE Symbolic Virtual Machine
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#
klee_add_component(kleeModule
	InstructionOperandTypeCheckPass.cpp
	IntrinsicCleaner.cpp
	KInstruction.cpp
	KModule.cpp
	LowerSwitch.cpp
	ModuleUtil.cpp
	PhiCleaner.cpp
	RaiseAsm.cpp
)

set(LLVM_COMPONENTS core passes support)
klee_get_llvm_libs(LLVM_LIBS ${LLVM_COMPONENTS})
target_link_libraries(kleeModule PUBLIC ${LLVM_LIBS})
