add_klee_unit_test(CoreTest AddressSpaceTest.cpp)

llvm_map_components_to_libnames(LLVM_LIBS core support transformutils scalaropts codegen)

target_link_libraries(CoreTest PRIVATE kleeCore kleeModule kleaverSolver kleaverExpr kleeSupport kleeBasic ${LLVM_LIBS})
