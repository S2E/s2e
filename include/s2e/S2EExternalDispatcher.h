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
    static jmp_buf s2e_escapeCallJmpBuf;

protected:
    virtual bool runProtectedCall(llvm::Function *f, uint64_t *args);

    static void s2e_ext_sigsegv_handler(int signal, siginfo_t *info, void *context);

public:
    S2EExternalDispatcher(llvm::LLVMContext &context) : ExternalDispatcher(context) {
    }

    void removeFunction(llvm::Function *f);

    static void saveJmpBuf();
    static void restoreJmpBuf();
};
}

#endif
