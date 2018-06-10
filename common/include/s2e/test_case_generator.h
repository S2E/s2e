/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2018 Cyberhaven
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

#ifndef S2E_TEST_CASE_GENERATOR_H
#define S2E_TEST_CASE_GENERATOR_H

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

enum S2E_TCGEN_COMMANDS {
    TCGEN_ADD_CONCRETE_FILE_CHUNK,
};

struct S2E_TCGEN_CONCRETE_FILE_CHUNK {
    // Guest pointer to a null-terminated string indicating the name of the file
    uint64_t name;

    // The offset in the file where this chunk starts
    uint64_t offset;

    // Guest pointer to chunk data
    uint64_t data;

    // The size of the chunk
    uint64_t size;
} __attribute__((packed));

struct S2E_TCGEN_COMMAND {
    enum S2E_TCGEN_COMMANDS Command;
    union {
        struct S2E_TCGEN_CONCRETE_FILE_CHUNK Chunk;
    };
} __attribute__((packed));

#ifdef __cplusplus
}
#endif

#endif
