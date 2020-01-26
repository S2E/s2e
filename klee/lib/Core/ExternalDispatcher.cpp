//===-- ExternalDispatcher.cpp --------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include <klee/ExternalDispatcher.h>
#include <llvm/Support/DynamicLibrary.h>

#include <iostream>
#include <setjmp.h>
#include <signal.h>
#include <sstream>

namespace klee {

ExternalDispatcher::ExternalDispatcher() {
}

ExternalDispatcher::~ExternalDispatcher() {
}

void *ExternalDispatcher::resolveSymbol(const std::string &name) {
    const char *str = name.c_str();

    // We use this to validate that function names can be resolved so we
    // need to match how the JIT does it. Unfortunately we can't
    // directly access the JIT resolution function
    // JIT::getPointerToNamedFunction so we emulate the important points.

    if (str[0] == 1) { // asm specifier, skipped
        ++str;
    }

    void *addr = llvm::sys::DynamicLibrary::SearchForAddressOfSymbol(str);
    if (addr) {
        return addr;
    }

    // If it has an asm specifier and starts with an underscore we retry
    // without the underscore. I (DWD) don't know why.
    if (name[0] == 1 && str[0] == '_') {
        ++str;
        addr = llvm::sys::DynamicLibrary::SearchForAddressOfSymbol(str);
    }

    return addr;
}

bool ExternalDispatcher::call(external_fcn_t targetFunction, const Arguments &args, uint64_t *result,
                              std::stringstream &err) {

    switch (args.size()) {
        case 0:
            *result = targetFunction();
            break;
        case 1:
            *result = targetFunction(args[0]);
            break;
        case 2:
            *result = targetFunction(args[0], args[1]);
            break;
        case 3:
            *result = targetFunction(args[0], args[1], args[2]);
            break;
        case 4:
            *result = targetFunction(args[0], args[1], args[2], args[3]);
            break;
        case 5:
            *result = targetFunction(args[0], args[1], args[2], args[3], args[4]);
            break;
        case 6:
            *result = targetFunction(args[0], args[1], args[2], args[3], args[4], args[5]);
            break;
        case 7:
            *result = targetFunction(args[0], args[1], args[2], args[3], args[4], args[5], args[6]);
            break;
        case 8:
            *result = targetFunction(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
            break;
        default: {
            err << "External function has too many parameters";
            return false;
        }
    }

    return true;
}
} // namespace klee
