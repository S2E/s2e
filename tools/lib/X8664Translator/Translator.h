///
/// Copyright (C) 2014-2017, Cyberhaven
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

#ifndef STATIC_X86TRANSLATOR_H

#define STATIC_X86TRANSLATOR_H

#include <llvm/ADT/SmallVector.h>
#include <llvm/Function.h>
#include <llvm/PassManager.h>
#include <llvm/Support/Path.h>

#include <vmi/ExecutableFile.h>

#include "lib/Utils/Log.h"

namespace s2etools {

class InvalidAddressException {
    uintptr_t m_address;
    unsigned m_size;

public:
    InvalidAddressException(uintptr_t address, unsigned size) {
        m_address = address;
        m_size = size;
    }

    uintptr_t getAddress() const {
        return m_address;
    }
};

class TranslatorNotInitializedException {};

class TranslatorException {
    std::string m_message;

public:
    TranslatorException(const std::string &msg) {
        m_message = msg;
    }
};

enum ETranslatedBlockType {
    BB_DEFAULT = 0,
    BB_JMP,
    BB_JMP_IND,
    BB_COND_JMP,
    BB_REP,
    BB_COND_JMP_IND,
    BB_CALL,
    BB_CALL_IND,
    BB_RET,
    BB_EXCP
};

/**
 * This holds a translated block of machine code to LLVM.
 * The block may correspond to one machine instruction or
 * contain the translation for several instructions, depending
 * on the translation mode.
 */
class TranslatedBlock {
public:
    typedef llvm::SmallVector<llvm::Value *, 2> Successors;

private:
    static LogKey TAG;

    /* Linear address of the instruction */
    uint64_t m_address;

    /* Raw LLVM representation of the instruction */
    llvm::Function *m_function;

    /* Successors */
    Successors m_successors;

    /* Type of the instruction determined by the translator */
    ETranslatedBlockType m_type;

    /* Size of the machine instruction */
    unsigned m_size;

public:
    TranslatedBlock() {
        m_address = 0;
        m_size = 0;
        m_function = NULL;
        m_type = BB_DEFAULT;
        m_successors.resize(2, NULL);
    }

    TranslatedBlock(uint64_t address, unsigned size, llvm::Function *f, ETranslatedBlockType type) {
        m_address = address;
        m_size = size;
        m_function = f;
        m_type = type;
        m_successors.resize(2, NULL);
    }

    llvm::Value *getFallback() const {
        return m_successors[0];
    }

    void setFallback(llvm::Value *v) {
        m_successors[0] = v;
    }

    llvm::Value *getDestination() const {
        return m_successors[1];
    }

    void setDestination(llvm::Value *v) {
        m_successors[1] = v;
    }

    bool isIndirectJump() const {
        return m_type == BB_JMP_IND || m_type == BB_COND_JMP_IND;
    }

    bool isCallInstruction() const {
        return m_type == BB_CALL || m_type == BB_CALL_IND;
    }

    bool operator<(const TranslatedBlock &bb) const {
        return m_address + m_size <= bb.m_address;
    }

    uint64_t getAddress() const {
        return m_address;
    }

    unsigned getSize() const {
        return m_size;
    }

    llvm::Function *getFunction() const {
        return m_function;
    }

    // Must not be used after the TB is created
    void setFunction(llvm::Function *func) {
        m_function = func;
    }

    ETranslatedBlockType getType() const {
        return m_type;
    }

    const Successors &getSuccessors() const {
        return m_successors;
    }

    void print(llvm::raw_ostream &os) const;
};

class Translator {
private:
    static LogKey TAG;
    const vmi::ExecutableFile *m_binary;
    static bool s_translatorInited;
    bool m_singlestep;

public:
    Translator(const llvm::sys::Path &bitcodeLibrary, const vmi::ExecutableFile *binary);

    virtual ~Translator();

    const vmi::ExecutableFile *getBinaryFile() const {
        return m_binary;
    }

    virtual TranslatedBlock *translate(uint64_t address) = 0;

    bool isInitialized() {
        return s_translatorInited;
    }

    virtual bool isSingleStep() const {
        return m_singlestep;
    }

    virtual void setSingleStep(bool b) {
        m_singlestep = b;
    }

    llvm::Module *getModule() const;
};

class X86Translator : public Translator {
public:
private:
    static LogKey TAG;
    llvm::FunctionPassManager *m_functionPasses;
    llvm::FunctionPassManager *m_functionOptPasses;

public:
    X86Translator(const llvm::sys::Path &bitcodeLibrary, const vmi::ExecutableFile *binary);
    virtual ~X86Translator();

    virtual TranslatedBlock *translate(uint64_t address);
};
} // namespace s2etools

#endif
