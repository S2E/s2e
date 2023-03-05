add_klee_unit_test(CoreTest AddressSpaceTest.cpp)

target_link_libraries(CoreTest PRIVATE kleeCore kleaverExpr kleeSupport)
