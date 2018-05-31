#===------------------------------------------------------------------------===#
#
#                     The KLEE Symbolic Virtual Machine
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#
klee_add_component(kleaverExpr
    BitfieldSimplifier.cpp
    CachedAssignmentEvaluator.cpp
    Constraints.cpp
    Expr.cpp
    ExprBuilder.cpp
    ExprEvaluator.cpp
    ExprPPrinter.cpp
    ExprSMTLIBPrinter.cpp
    ExprUtil.cpp
    ExprVisitor.cpp
    Lexer.cpp
    Parser.cpp
    Updates.cpp
)

set(LLVM_COMPONENTS
  support
)

klee_get_llvm_libs(LLVM_LIBS ${LLVM_COMPONENTS})
target_link_libraries(kleaverExpr PUBLIC ${LLVM_LIBS})
