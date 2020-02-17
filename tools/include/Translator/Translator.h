///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
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
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/Path.h>

#include <vmi/ExecutableFile.h>
#include "lib/Utils/Log.h"

class TCGLLVMTranslator;

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
    typedef llvm::SmallVector<uint64_t, 2> Successors;
    typedef llvm::SmallVector<llvm::StoreInst *, 4> Stores;

private:
    static LogKey TAG;

    /* Linear address of the instruction */
    uint64_t m_address;

    /* Address of the last instruction */
    uint64_t m_lastAddress;

    /* Raw LLVM representation of the instruction */
    llvm::Function *m_function;

    /* Successors */
    Successors m_successors;

    /* Last instructions that assign the program counter */
    Stores m_lastPcAssignments;

    /* Type of the instruction determined by the translator */
    ETranslatedBlockType m_type;

    /* Size of the machine instruction */
    unsigned m_size;

public:
    TranslatedBlock() {
        m_address = 0;
        m_lastAddress = 0;
        m_size = 0;
        m_function = NULL;
        m_type = BB_DEFAULT;
    }

    TranslatedBlock(uint64_t address, uint64_t lastAddress, unsigned size, llvm::Function *f, ETranslatedBlockType type,
                    const Successors &succs, const Stores &pcstores) {
        m_address = address;
        m_lastAddress = lastAddress;
        m_size = size;
        m_function = f;
        m_type = type;
        m_successors = succs;
        m_lastPcAssignments = pcstores;
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

    uint64_t getLastAddress() const {
        return m_lastAddress;
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

    const Stores &getLastPcAssignments() const {
        return m_lastPcAssignments;
    }

    llvm::StoreInst *getLastPcAssignment() const {
        assert(m_lastPcAssignments.size() >= 1);
        return m_lastPcAssignments.back();
    }

    inline uint64_t getSuccessor(unsigned i) const {
        return m_successors[i];
    }

    void print(llvm::raw_ostream &os) const;
};

class Translator {
public:
    struct RegisterMask {
        uint64_t rmask, wmask, accesses_mem;
    };

    typedef llvm::SmallVector<llvm::Function *, 4> MemoryWrappers;

private:
    static LogKey TAG;
    std::shared_ptr<const vmi::ExecutableFile> m_binary;
    static bool s_translatorInited;
    bool m_singlestep;
    std::unique_ptr<llvm::Module> m_module;

protected:
    TCGLLVMTranslator *m_ctx;

public:
    Translator(const std::string &bitcodeLibrary, const std::shared_ptr<vmi::ExecutableFile> binary);

    virtual ~Translator();

    const std::shared_ptr<const vmi::ExecutableFile> getBinaryFile() const {
        return m_binary;
    }

    virtual TranslatedBlock *translate(uint64_t address, uint64_t lastAddress) = 0;

    bool isInitialized() {
        return s_translatorInited;
    }

    virtual bool isSingleStep() const {
        return m_singlestep;
    }

    virtual void setSingleStep(bool b) {
        m_singlestep = b;
    }

    static void getRetInstructions(llvm::Function *f, llvm::SmallVector<llvm::ReturnInst *, 2> &ret);

    llvm::Module *getModule() const;

    llvm::Function *createTbFunction(const std::string &name) const;
    llvm::FunctionType *getTbType() const;

    static unsigned getTargetPtrSizeInBytes();
    static bool isGpRegister(llvm::Value *gep, unsigned reg);
    static bool isGpRegister(llvm::Value *gep, unsigned *regIndex = NULL);
    static bool isPcRegister(llvm::Value *gep);

    static void getWrappers(llvm::Module &M, MemoryWrappers &wrappers, const char **names);
    static void getStoreWrappers(llvm::Module &M, MemoryWrappers &wrappers);
    static void getLoadWrappers(llvm::Module &M, MemoryWrappers &wrappers);

    static llvm::Value *getPcPtr(llvm::IRBuilder<> &builder);

    static RegisterMask getRegisterMaskForHelper(llvm::Function *helper);
    static uint64_t getRegisterBitMask(llvm::Value *gep);
};

class X86Translator : public Translator {
public:
private:
    static LogKey TAG;
    static const char *s_regNames[8];
    llvm::legacy::FunctionPassManager *m_functionPasses;
    llvm::legacy::FunctionPassManager *m_functionOptPasses;

public:
    X86Translator(const std::string &bitcodeLibrary, const std::shared_ptr<vmi::ExecutableFile> binary);
    virtual ~X86Translator();

    virtual TranslatedBlock *translate(uint64_t address, uint64_t lastAddress);

    enum Registers {
        // REG_ prevents collisions with QEMU
        REG_EAX = 0,
        REG_ECX = 1,
        REG_EDX = 2,
        REG_EBX = 3,
        REG_ESP = 4,
        REG_EBP = 5,
        REG_ESI = 6,
        REG_EDI = 7
    };

    static std::string getRegisterName(unsigned reg) {
        assert(reg < 8);
        return s_regNames[reg];
    }
};
} // namespace s2etools

#endif
