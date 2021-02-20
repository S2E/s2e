//===-- ModuleUtil.cpp ----------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Internal/Support/ModuleUtil.h"
#include <klee/Common.h>

#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/IR/AssemblyAnnotationWriter.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Linker/Linker.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"

#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>

using namespace llvm;
using namespace klee;

Module *klee::linkWithLibrary(Module *module, const std::string &libraryName) {
    auto ErrorOrMemBuff = MemoryBuffer::getFile(libraryName);
    if (std::error_code EC = ErrorOrMemBuff.getError()) {
        pabort("Reading library failed!");
    }

    auto ErrorOrMod = parseBitcodeFile(ErrorOrMemBuff.get()->getMemBufferRef(), module->getContext());

    Linker linker(*module);

    if (linker.linkInModule(std::move(ErrorOrMod.get()))) {
        pabort("linking in library failed!");
    }

    return module;
}
