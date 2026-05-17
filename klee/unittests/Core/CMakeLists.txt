add_klee_unit_test(CoreTest AddressSpaceTest.cpp)
add_klee_unit_test(ExecutorTest ExecutorTest.cpp)

llvm_map_components_to_libnames(LLVM_LIBS core support transformutils scalaropts codegen)
llvm_map_components_to_libnames(LLVM_EXECUTOR_LIBS core support transformutils scalaropts codegen passes analysis ipo bitreader)

target_link_libraries(CoreTest PRIVATE kleeCore kleeModule kleaverSolver kleaverExpr kleeSupport kleeBasic ${LLVM_LIBS})
target_link_libraries(ExecutorTest PRIVATE kleeCore kleeModule kleaverSolver kleaverExpr kleeSupport kleeBasic ${LLVM_EXECUTOR_LIBS})

# Compile C sources to LLVM bitcode and expose their paths to the test.
find_program(CLANG_EXECUTABLE NAMES clang-19 clang REQUIRED)

foreach(src add compute function)
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${src}.bc
        COMMAND ${CLANG_EXECUTABLE} -emit-llvm -c -O0
                ${CMAKE_CURRENT_SOURCE_DIR}/LLVM/${src}.c
                -o ${CMAKE_CURRENT_BINARY_DIR}/${src}.bc
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/LLVM/${src}.c
        COMMENT "Compiling ${src}.c to LLVM bitcode"
    )
    add_custom_target(${src}_bc DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${src}.bc)
    add_dependencies(ExecutorTest ${src}_bc)
endforeach()

target_compile_definitions(ExecutorTest PRIVATE
    ADD_BC_PATH="${CMAKE_CURRENT_BINARY_DIR}/add.bc"
    COMPUTE_BC_PATH="${CMAKE_CURRENT_BINARY_DIR}/compute.bc"
    FUNCTION_BC_PATH="${CMAKE_CURRENT_BINARY_DIR}/function.bc"
)
