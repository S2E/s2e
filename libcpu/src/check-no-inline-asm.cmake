# Fails the build if the bitcode library contains inline assembly.
#
# KLEE cannot interpret inline assembly and terminates any state that reaches
# it. Host headers often have x86 inline-asm fast paths, which the bitcode
# build must disable with SYMBEX_LLVM_LIB.
#
# Usage: cmake -DLLVM_DIS=<llvm-dis> -DBITCODE=<file.bc> -P check-no-inline-asm.cmake

execute_process(
    COMMAND ${LLVM_DIS} ${BITCODE} -o -
    OUTPUT_VARIABLE IR
    RESULT_VARIABLE RES
)

if (NOT RES EQUAL 0)
    message(FATAL_ERROR "${LLVM_DIS} failed on ${BITCODE}")
endif ()

# Inline assembly appears as "call <type> asm [sideeffect] ..." (or invoke and
# callbr) in function bodies, and as "module asm ..." at the top level. The
# text between the call keyword and "asm" may not contain "@" or a quote, so
# that a callee or a string constant that contains " asm " does not match.
string(REGEX MATCHALL "\n[^\n\"@]*(call|invoke|callbr) [^\n\"@]*asm [^\n]*" ASM_CALLS "${IR}")
string(REGEX MATCHALL "\nmodule asm [^\n]*" ASM_MODULE "${IR}")
set(ASM_LINES ${ASM_CALLS} ${ASM_MODULE})

if (ASM_LINES)
    list(LENGTH ASM_LINES COUNT)
    string(REPLACE ";" "" ASM_TEXT "${ASM_LINES}")
    message(FATAL_ERROR "${BITCODE} contains ${COUNT} inline assembly statements:${ASM_TEXT}")
endif ()
