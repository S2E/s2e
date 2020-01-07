///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
}
