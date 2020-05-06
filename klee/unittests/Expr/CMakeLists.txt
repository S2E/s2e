add_klee_unit_test(ExprTest ExprTest.cpp BitfieldSimplifier.cpp)

target_link_libraries(ExprTest PRIVATE kleaverExpr kleeCore kleeSupport)
