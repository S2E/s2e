///
/// Copyright (C) 2012-2014, Dependable Systems Laboratory, EPFL
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

#ifndef _THREAD_DESCRIPTOR_H_

#define _THREAD_DESCRIPTOR_H_

#include <inttypes.h>

namespace s2e {

struct ThreadDescriptor {
    uint64_t Pid;
    uint64_t Tid;
    uint64_t KernelStackBottom;
    uint64_t KernelStackSize;

    bool KernelMode;
    // TODO: add other interesting information

    ThreadDescriptor() {
        Pid = Tid = 0;
        KernelStackBottom = 0;
        KernelStackSize = 0;
        KernelMode = false;
    }
};
} // namespace s2e

#endif
