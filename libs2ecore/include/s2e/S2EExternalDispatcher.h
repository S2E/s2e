///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2019, Cyberhaven
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

#ifndef _S2E_EXTERNAL_DISPATCHER_H

#define _S2E_EXTERNAL_DISPATCHER_H

#include <inttypes.h>
#include <klee/ExternalDispatcher.h>
#include <llvm/IR/Function.h>
#include <setjmp.h>
#include <signal.h>

namespace s2e {

/* External dispatcher to convert longjmp's into C++ exceptions */
class S2EExternalDispatcher : public klee::ExternalDispatcher {
private:
    // FIXME: This is not reentrant.
    static jmp_buf s2e_cpuExitJmpBuf;

public:
    S2EExternalDispatcher();
    virtual ~S2EExternalDispatcher();

    static void saveJmpBuf();
    static void restoreJmpBuf();

    virtual bool call(external_fcn_t targetFunction, const Arguments &args, uint64_t *result, std::stringstream &err);
};
} // namespace s2e

#endif
