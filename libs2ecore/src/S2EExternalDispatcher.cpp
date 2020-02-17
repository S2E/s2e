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

#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/GenericValue.h>

#include <s2e/S2EExecutor.h>
#include <s2e/S2EExternalDispatcher.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>
#include <s2e/s2e_config.h>

using namespace llvm;

namespace s2e {

jmp_buf S2EExternalDispatcher::s2e_cpuExitJmpBuf;

S2EExternalDispatcher::S2EExternalDispatcher() {
}

S2EExternalDispatcher::~S2EExternalDispatcher() {
}

bool S2EExternalDispatcher::call(external_fcn_t targetFunction, const Arguments &args, uint64_t *result,
                                 std::stringstream &err) {
    bool res;

    saveJmpBuf();

    if (setjmp(env->jmp_env)) {
        restoreJmpBuf();
        throw CpuExitException();
    } else {
        res = ExternalDispatcher::call(targetFunction, args, result, err);
    }

    restoreJmpBuf();

    return res;
}

void S2EExternalDispatcher::saveJmpBuf() {
    memcpy(s2e_cpuExitJmpBuf, env->jmp_env, sizeof(env->jmp_env));
}

void S2EExternalDispatcher::restoreJmpBuf() {
    memcpy(env->jmp_env, s2e_cpuExitJmpBuf, sizeof(env->jmp_env));
}
} // namespace s2e
