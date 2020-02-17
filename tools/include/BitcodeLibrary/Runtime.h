///
/// Copyright (C) 2015-2017, Cyberhaven
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///

#ifndef __REVGEN_RUNTIME_H__

#define __REVGEN_RUNTIME_H__

#include <inttypes.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CPUX86State CPUX86State;

typedef uint64_t (*revgen_function_t)(CPUX86State *env);

uint64_t revgen_entrypoint(CPUX86State *env);

extern uint64_t revgen_function_count;
extern revgen_function_t *revgen_function_pointers;
extern uint64_t *revgen_function_addresses;

int __detect_library_functions(int argc, char **argv);
extern int __revgen_detect_library_functions;

static inline void dosegfault(void) {
    volatile char *v = NULL;
    *v = 0;
}

void __revgen_validate_pointer(uint64_t pointer);

#ifdef __cplusplus
}
#endif

#endif
