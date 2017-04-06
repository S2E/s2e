/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2016 Cyberhaven
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

#ifndef S2E_SEED_COMMANDS_H
#define S2E_SEED_COMMANDS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>

enum S2E_SEEDSEARCHER_COMMANDS {
    SEED_GET_SEED_FILE,
    SEED_ENABLE_SEARCHER,
    SEED_DONE,
};

struct S2E_SEEDSEARCHER_COMMAND_GETFILE {
    /// Pointer to guest memory where the plugin will store the file name
    uint64_t FileName;

    /// Size of the buffer in bytes, including null character
    uint64_t FileNameSizeInBytes;

    /// 1 on success, 0 on failure (no seed file available)
    uint64_t Result;
} __attribute__((packed));

struct S2E_SEEDSEARCHER_COMMAND {
    enum S2E_SEEDSEARCHER_COMMANDS Command;
    union {
        struct S2E_SEEDSEARCHER_COMMAND_GETFILE GetFile;
    };
} __attribute__((packed));

#ifdef __cplusplus
}
#endif

#endif
