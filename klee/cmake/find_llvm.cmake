#===------------------------------------------------------------------------===#
#
#                     The KLEE Symbolic Virtual Machine
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#

find_package(LLVM CONFIG REQUIRED)

# Provide function to map LLVM components to libraries.
function(klee_get_llvm_libs output_var)
    llvm_map_components_to_libnames(${output_var} ${ARGN})
endfunction()
