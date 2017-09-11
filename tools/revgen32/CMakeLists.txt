# Copyright (c) 2017 Dependable Systems Laboratory, EPFL
# Copyright (c) 2017 Cyberhaven
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

set(REVGEN64_DIR ${CMAKE_SOURCE_DIR}/tools/revgen64)

add_executable(revgen32 ${REVGEN64_DIR}/RevGen.cpp
                        ${REVGEN64_DIR}/MemoryWrapperElimination.cpp
                        ${REVGEN64_DIR}/RegisterPromotion.cpp
                        ${REVGEN64_DIR}/InstructionLabeling.cpp)
target_include_directories(revgen32 PRIVATE ${CMAKE_BINARY_DIR})
target_link_libraries(revgen32 X86Translator
                               cfg
                               utils
                               vmi
                               bsd
                               fsigc++
                               elf
                               ${LLVM_LIBS}
                               ${GLIB2_LIBRARIES})

install(TARGETS revgen32 RUNTIME DESTINATION bin)
