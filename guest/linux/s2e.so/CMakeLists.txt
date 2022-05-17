# S2E Selective Symbolic Execution Platform
#
# Copyright (c) 2017 Dependable Systems Laboratory, EPFL
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


add_library(s2e SHARED
    main.c s2e.c elf.c procmap.c modules.c s2e.c
    ../function_models/libc_wrapper.c
    ../function_models/libz_wrapper.c
    ../function_models/models.c
)

target_link_libraries(s2e dl elf)
set_target_properties(s2e PROPERTIES POSITION_INDEPENDENT_CODE ON)

# We want it to be called s2e.so, not libs2e.so
set_target_properties(s2e PROPERTIES PREFIX "")

install(TARGETS s2e LIBRARY DESTINATION .)
