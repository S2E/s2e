add_klee_unit_test(ExprTest ExprTest.cpp BitfieldSimplifier.cpp)

llvm_map_components_to_libnames(LLVM_LIBS core support transformutils scalaropts codegen)

target_link_libraries(ExprTest PRIVATE kleeCore kleaverSolver kleaverExpr kleeModule kleeSupport kleeBasic ${LLVM_LIBS})
