//===-- ModuleUtil.h --------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_TRANSFORM_UTIL_H
#define KLEE_TRANSFORM_UTIL_H

#include <string>

namespace llvm {
class Function;
class Instruction;
class Module;
} // namespace llvm

namespace klee {

/// Link a module with a specified bitcode archive.
llvm::Module *linkWithLibrary(llvm::Module *module, const std::string &libraryName);

} // namespace klee

#endif
