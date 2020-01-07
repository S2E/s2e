///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
}

#endif
