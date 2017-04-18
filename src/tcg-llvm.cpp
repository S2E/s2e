/*
 * Tiny Code Generator for QEMU - LLVM Backend
 *
 * Copyright (c) 2017, Cyberhaven
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

extern "C" {
#include <tcg/tcg.h>
}

#include <tcg/tcg-llvm.h>

#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/Threading.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Scalar/GVN.h>

#include <llvm/Support/DynamicLibrary.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/raw_ostream.h>

#include <llvm/ADT/DenseMap.h>

#include <iostream>
#include <sstream>
#include <sys/types.h>
#include <unistd.h>

#if TARGET_LONG_BITS == 32
typedef uint32_t target_ulong;
#else
typedef uint64_t target_ulong;
#endif

// XXX: hack
#define CC_OP_DYNAMIC 0

//#undef NDEBUG
#define USE_GEPS

// XXX: clang format gives really ugly results
// for this file. Looks like the file needs to be
// manually refactored.
// clang-format off

extern "C" {
    TCGLLVMContext* tcg_llvm_ctx = 0;

    /* These data is accessible from generated code */
    TCGLLVMRuntime tcg_llvm_runtime = {
        0, 0, {0,0,0}
#ifdef CONFIG_SYMBEX
        , 0
#endif
#ifndef CONFIG_SYMBEX
        , 0, 0, 0
#endif
    };

}

using namespace llvm;

struct TCGLLVMContextPrivate {
    LLVMContext& m_context;
    IRBuilder<> m_builder;

    /* Current m_module */
    Module *m_module;

    /* Function pass manager (used for optimizing the code) */
    legacy::FunctionPassManager *m_functionPassManager;

#ifdef CONFIG_SYMBEX
    /* Declaration of a wrapper function for helpers */
    Function *m_helperTraceMemoryAccess;
    Function *m_helperTraceInstruction;
    Function *m_helperForkAndConcretize;
    Function *m_helperGetValue;
    Function* m_qemu_ld_helpers[5];
    Function* m_qemu_st_helpers[5];
#endif

#ifdef STATIC_TRANSLATOR
    TCGLLVMTBInfo m_info;
#endif

    /* Count of generated translation blocks */
    int m_tbCount;

    /* XXX: The following members are "local" to generateCode method */

    /* TCGContext for current translation block */
    TCGContext* m_tcgContext;

    /* Function for current translation block */
    Function *m_tbFunction;

    /* Current temp m_values */
    Value* m_values[TCG_MAX_TEMPS];

    /* Pointers to in-memory versions of globals or local temps */
    Value* m_memValuesPtr[TCG_MAX_TEMPS];

    /* For reg-based globals, store argument number,
     * for mem-based globals, store base value index */
    int m_globalsIdx[TCG_MAX_TEMPS];

    BasicBlock* m_labels[TCG_MAX_LABELS];

    FunctionType *m_tbType;
    Type *m_cpuType;
    Value *m_cpuState;
    Value *m_eip;
    Value *m_ccop;

    typedef DenseMap<unsigned, Value *> GepMap;
    GepMap m_registers;

    std::string generateName();

public:
    TCGLLVMContextPrivate(LLVMContext&);
    ~TCGLLVMContextPrivate();

    legacy::FunctionPassManager *getFunctionPassManager() const {
        return m_functionPassManager;
    }

    bool isInstrumented(llvm::Function *tb);

    /* Shortcuts */
    Type* intType(int w) { return IntegerType::get(m_context, w); }
    Type* intPtrType(int w) { return PointerType::get(intType(w), 0); }
    Type* wordType() { return intType(TCG_TARGET_REG_BITS); }
    Type* wordType(int bits) { return intType(bits); }
    Type* wordPtrType() { return intPtrType(TCG_TARGET_REG_BITS); }
    FunctionType* tbType() {
        if (m_tbType) {
            return m_tbType;
        }
        SmallVector<Type*,1> args;
        #ifdef STATIC_TRANSLATOR
        args.push_back(m_cpuType->getPointerTo());
        #else
        args.push_back(intPtrType(64));
        #endif
        m_tbType = FunctionType::get(wordType(), args, false);
        return m_tbType;
    }

    void adjustTypeSize(unsigned target, Value **v1) {
        Value *va = *v1;
        if (target == 32) {
            if (va->getType() == intType(64)) {
                *v1 = m_builder.CreateTrunc(va, intType(target));
            } else if (va->getType() != intType(32)) {
                assert(false);
            }
        }
    }

    Value* generateCpuStatePtr(TCGArg arg, unsigned sizeInBytes);
    void generateQemuCpuLoad(const TCGArg *args, unsigned memBits, unsigned regBits, bool signExtend);
    void generateQemuCpuStore(const TCGArg *args, unsigned memBits, Value *valueToStore);

#ifdef STATIC_TRANSLATOR
    uint64_t m_currentPc;
    void attachPcMetadata(Instruction *instr, uint64_t pc);
#endif
    Value *attachCurrentPc(Value *value);

    //This handles the special case of symbolic values
    //assigned to the program counter register
    Value* handleSymbolicPcAssignment(Value *orig) {
#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
        if (isa<ConstantInt>(orig)) {
            return orig;
        }
        std::vector<Value*> argValues;
        Type *t = intType(TARGET_LONG_BITS);
        argValues.push_back(orig);
        argValues.push_back(ConstantInt::get(t, 0));
        argValues.push_back(ConstantInt::get(t, (target_ulong)-1));
        argValues.push_back(ConstantInt::get(t, 1));
        Value *valueToStore = m_builder.CreateCall(m_helperForkAndConcretize,
                                                   ArrayRef<Value*>(argValues));

        valueToStore = m_builder.CreateTrunc(valueToStore,
                                             intType(TARGET_LONG_BITS));
        return valueToStore;
#else
        return orig;
#endif
    }

#ifdef STATIC_TRANSLATOR
    bool isPcAssignment(Value *v) {
        return v == m_eip;
    }

    const TCGLLVMTBInfo &getTbInfo() const {
        return m_info;
    }

    void computeStaticBranchTargets();
#endif

    void adjustTypeSize(unsigned target, Value **v1, Value **v2) {
        adjustTypeSize(target, v1);
        adjustTypeSize(target, v2);
    }

    Type* tcgType(int type) {
        return type == TCG_TYPE_I64 ? intType(64) : intType(32);
    }

    Type* tcgPtrType(int type) {
        return type == TCG_TYPE_I64 ? intPtrType(64) : intPtrType(32);
    }

    /* Helpers */
    Value* getValue(int idx);
    void setValue(int idx, Value *v);
    void delValue(int idx);

    Value* getPtrForValue(int idx);
    void delPtrForValue(int idx);
    void initGlobalsAndLocalTemps();
    void loadNativeCpuState(Function *f);
    unsigned getValueBits(int idx);

    void invalidateCachedMemory();

    uint64_t toInteger(Value *v) const {
        if (ConstantInt *cste = dyn_cast<ConstantInt>(v)) {
            return *cste->getValue().getRawData();
        }

        llvm::errs() << *v << '\n';
        assert(false && "Not a constant");
        abort();
    }
#ifdef CONFIG_SYMBEX
    void initializeHelpers();
    void initializeNativeCpuState();
#endif

    BasicBlock* getLabel(int idx);
    void delLabel(int idx);
    void startNewBasicBlock(BasicBlock *bb = NULL);

    /* Code generation */
    Value* generateQemuMemOp(bool ld, Value *value, Value *addr,
                             int mem_index, int bits);

    void generateTraceCall(uintptr_t pc);
    int generateOperation(int opc, const TCGArg *args);

    Function *createTbFunction(const std::string &name);
    Function *generateCode(TCGContext *s);
};

TCGLLVMContextPrivate::TCGLLVMContextPrivate(LLVMContext& context)
    : m_context(context), m_builder(m_context), m_tbCount(0),
      m_tcgContext(NULL), m_tbFunction(NULL), m_tbType(NULL)
{
    std::memset(m_values, 0, sizeof(m_values));
    std::memset(m_memValuesPtr, 0, sizeof(m_memValuesPtr));
    std::memset(m_globalsIdx, 0, sizeof(m_globalsIdx));
    std::memset(m_labels, 0, sizeof(m_labels));

    m_module = new Module("tcg-llvm", m_context);

    InitializeNativeTarget();

    std::string error;
    ExecutionEngine* engine = EngineBuilder(std::unique_ptr<Module>(m_module))
                              .setErrorStr(&error)
                              .create();

    if (!engine) {
        std::cerr << "Unable to create LLVM JIT: " << error << std::endl;
        exit(1);
    }

    DataLayout nativeLayout = engine->getDataLayout();
    engine->removeModule(m_module);
    m_module->setDataLayout(nativeLayout);

    m_functionPassManager = new legacy::FunctionPassManager(m_module);
    m_functionPassManager->add(createReassociatePass());
    m_functionPassManager->add(createConstantPropagationPass());
    m_functionPassManager->add(createInstructionCombiningPass());
    m_functionPassManager->add(createGVNPass());
    m_functionPassManager->add(createDeadStoreEliminationPass());
    m_functionPassManager->add(createCFGSimplificationPass());
    m_functionPassManager->add(createPromoteMemoryToRegisterPass());

    m_functionPassManager->doInitialization();

    m_cpuType = NULL;
    m_cpuState = NULL;
    m_eip = NULL;
    m_ccop = NULL;
}

TCGLLVMContextPrivate::~TCGLLVMContextPrivate()
{
    delete m_functionPassManager;
}

#ifdef CONFIG_SYMBEX

void TCGLLVMContextPrivate::initializeNativeCpuState()
{
    m_cpuType = m_module->getTypeByName("struct.CPUX86State");
    assert(m_cpuType && "Could not find CPUX86State in LLVM bitcode");
}


void TCGLLVMContextPrivate::initializeHelpers()
{
    m_helperTraceMemoryAccess =
            m_module->getFunction("tcg_llvm_after_memory_access");

    m_helperTraceInstruction =
            m_module->getFunction("tcg_llvm_trace_instruction");

    m_helperForkAndConcretize =
            m_module->getFunction("tcg_llvm_fork_and_concretize");

    m_helperGetValue =
            m_module->getFunction("tcg_llvm_get_value");

    m_qemu_ld_helpers[0] = m_module->getFunction("__ldb_mmu");
    m_qemu_ld_helpers[1] = m_module->getFunction("__ldw_mmu");
    m_qemu_ld_helpers[2] = m_module->getFunction("__ldl_mmu");
    m_qemu_ld_helpers[3] = m_module->getFunction("__ldq_mmu");
    m_qemu_ld_helpers[4] = m_module->getFunction("__ldq_mmu");

    m_qemu_st_helpers[0] = m_module->getFunction("__stb_mmu");
    m_qemu_st_helpers[1] = m_module->getFunction("__stw_mmu");
    m_qemu_st_helpers[2] = m_module->getFunction("__stl_mmu");
    m_qemu_st_helpers[3] = m_module->getFunction("__stq_mmu");
    m_qemu_st_helpers[4] = m_module->getFunction("__stq_mmu");

    #ifndef STATIC_TRANSLATOR
    assert(m_helperTraceMemoryAccess);
    assert(m_helperGetValue);
    #endif

    for(int i = 0; i < 5; ++i) {
        if (!m_qemu_ld_helpers[i]) {
            abort();
        }

        if (!m_qemu_st_helpers[i]) {
            abort();
        }
    }
}
#endif

#ifdef STATIC_TRANSLATOR
void TCGLLVMContextPrivate::attachPcMetadata(Instruction *instr, uint64_t pc)
{
    LLVMContext& C = instr->getContext();
    SmallVector<Metadata*, 1> args;
    args.push_back(ValueAsMetadata::get(ConstantInt::get(wordType(64), pc)));
    MDNode* N = MDNode::get(C, ArrayRef<Metadata*>(args));
    instr->setMetadata("s2e.pc", N);
}

Value *TCGLLVMContextPrivate::attachCurrentPc(Value *v)
{
    Instruction *instr = dynamic_cast<Instruction*>(v);
    if (instr) {
        attachPcMetadata(instr, m_currentPc);
    }
    return v;
}
#else
Value *TCGLLVMContextPrivate::attachCurrentPc(Value *v)
{
    return v;
}
#endif

Value* TCGLLVMContextPrivate::getPtrForValue(int idx)
{
    TCGContext *s = m_tcgContext;
    TCGTemp &temp = s->temps[idx];

    assert(idx < s->nb_globals || s->temps[idx].temp_local);

    if(m_memValuesPtr[idx] == NULL) {
        assert(idx < s->nb_globals);

        if(temp.fixed_reg) {
            Value *v = m_builder.CreateConstGEP1_32(
                    &*(m_tbFunction->arg_begin()), m_globalsIdx[idx]);
            m_memValuesPtr[idx] = m_builder.CreatePointerCast(
                    v, tcgPtrType(temp.type)
#ifndef NDEBUG
                    , StringRef(temp.name) + "_ptr"
#endif
                    );

        } else {
#if defined(USE_GEPS)
            m_memValuesPtr[idx] =
                generateCpuStatePtr(temp.mem_offset, tcgType(temp.type)->getScalarSizeInBits() / 8);
#endif

            if (!m_memValuesPtr[idx]) {
                Value *v = getValue(m_globalsIdx[idx]);
                assert(v->getType() == wordType());
                v = m_builder.CreateAdd(v, ConstantInt::get(
                                wordType(), temp.mem_offset));
                m_memValuesPtr[idx] =
                    m_builder.CreateIntToPtr(v, tcgPtrType(temp.type)
    #ifndef NDEBUG
                            , StringRef(temp.name) + "_ptr"
    #endif
                            );
            }

        }
    }

    return m_memValuesPtr[idx];
}

inline void TCGLLVMContextPrivate::delValue(int idx)
{
    /* XXX
    if(m_values[idx] && m_values[idx]->use_empty()) {
        if(!isa<Instruction>(m_values[idx]) ||
                !cast<Instruction>(m_values[idx])->getParent())
            delete m_values[idx];
    }
    */
    m_values[idx] = NULL;
}

inline void TCGLLVMContextPrivate::delPtrForValue(int idx)
{
    /* XXX
    if(m_memValuesPtr[idx] && m_memValuesPtr[idx]->use_empty()) {
        if(!isa<Instruction>(m_memValuesPtr[idx]) ||
                !cast<Instruction>(m_memValuesPtr[idx])->getParent())
            delete m_memValuesPtr[idx];
    }
    */
    m_memValuesPtr[idx] = NULL;
}

unsigned TCGLLVMContextPrivate::getValueBits(int idx)
{
    switch (m_tcgContext->temps[idx].type) {
        case TCG_TYPE_I32: return 32;
        case TCG_TYPE_I64: return 64;
        default: assert(false && "Unknown size");
    }
    return 0;
}

Value* TCGLLVMContextPrivate::getValue(int idx)
{
    if(m_values[idx] == NULL) {
        if(idx < m_tcgContext->nb_globals) {
#ifdef STATIC_TRANSLATOR
            if (idx == 0) {
                return m_builder.CreatePtrToInt(m_cpuState, wordType());
            }
#endif

            m_values[idx] = m_builder.CreateLoad(getPtrForValue(idx)
#ifndef NDEBUG
                    , StringRef(m_tcgContext->temps[idx].name) + "_v"
#endif
                    );
        } else if(m_tcgContext->temps[idx].temp_local) {
            m_values[idx] = m_builder.CreateLoad(getPtrForValue(idx));
#ifndef NDEBUG
            std::ostringstream name;
            name << "loc" << (idx - m_tcgContext->nb_globals) << "_v";
            m_values[idx]->setName(name.str());
#endif
        } else {
            // Temp value was not previousely assigned
            assert(false); // XXX: or return zero constant ?
        }
    }

#ifdef STATIC_TRANSLATOR
    return attachCurrentPc(m_values[idx]);
#else
    return m_values[idx];
#endif
}

void TCGLLVMContextPrivate::setValue(int idx, Value *v)
{
    delValue(idx);
    m_values[idx] = v;

    if(!v->hasName() && !isa<Constant>(v)) {
#ifndef NDEBUG
        if(idx < m_tcgContext->nb_globals)
            v->setName(StringRef(m_tcgContext->temps[idx].name) + "_v");
        if(m_tcgContext->temps[idx].temp_local) {
            std::ostringstream name;
            name << "loc" << (idx - m_tcgContext->nb_globals) << "_v";
            v->setName(name.str());
        } else {
            std::ostringstream name;
            name << "tmp" << (idx - m_tcgContext->nb_globals) << "_v";
            v->setName(name.str());
        }
#endif
    }

    if(idx < m_tcgContext->nb_globals) {
        // We need to save a global copy of a value
        m_builder.CreateStore(v, getPtrForValue(idx));

        if(m_tcgContext->temps[idx].fixed_reg) {
            /* Invalidate all dependent global vals and pointers */
            for(int i=0; i<m_tcgContext->nb_globals; ++i) {
                if(i != idx && !m_tcgContext->temps[idx].fixed_reg &&
                                    m_globalsIdx[i] == idx) {
                    delValue(i);
                    delPtrForValue(i);
                }
            }
        }
    } else if(m_tcgContext->temps[idx].temp_local) {
        // We need to save an in-memory copy of a value
        m_builder.CreateStore(v, getPtrForValue(idx));
    }
}

void TCGLLVMContextPrivate::initGlobalsAndLocalTemps()
{
    TCGContext *s = m_tcgContext;

    int reg_to_idx[TCG_TARGET_NB_REGS];
    for(int i=0; i<TCG_TARGET_NB_REGS; ++i)
        reg_to_idx[i] = -1;

    int argNumber = 0;
    for(int i=0; i<s->nb_globals; ++i) {
        if(s->temps[i].fixed_reg) {
            // This global is in fixed host register. We are
            // mapping such registers to function arguments
            m_globalsIdx[i] = argNumber++;
            reg_to_idx[s->temps[i].reg] = i;

        } else {
            // This global is in memory at (mem_reg + mem_offset).
            // Base value is not known yet, so just store mem_reg
            m_globalsIdx[i] = s->temps[i].mem_reg;
        }
    }

    // Map mem_reg to index for memory-based globals
    for(int i=0; i<s->nb_globals; ++i) {
        if(!s->temps[i].fixed_reg) {
            assert(reg_to_idx[m_globalsIdx[i]] >= 0);
            m_globalsIdx[i] = reg_to_idx[m_globalsIdx[i]];
        }
    }

    // Allocate local temps
    for(int i=s->nb_globals; i<TCG_MAX_TEMPS; ++i) {
        if(s->temps[i].temp_local) {
            std::ostringstream pName;
            pName << "loc_" << (i - s->nb_globals) << "ptr";
            m_memValuesPtr[i] = m_builder.CreateAlloca(
                tcgType(s->temps[i].type), 0, pName.str());
        }
    }
}

void TCGLLVMContextPrivate::loadNativeCpuState(Function *f)
{
#ifdef STATIC_TRANSLATOR
    m_cpuState = &*(f->arg_begin());
#else
    m_cpuState = m_builder.CreateIntToPtr(getValue(0), m_cpuType->getPointerTo(), "state");
#endif
    /* Reinitialize left overs */
    m_eip = NULL;
    m_ccop = NULL;
    m_eip = generateCpuStatePtr(m_tcgContext->env_offset_eip, m_tcgContext->env_sizeof_eip);
    m_ccop = generateCpuStatePtr(m_tcgContext->env_offset_ccop, m_tcgContext->env_sizeof_ccop);
}

inline BasicBlock* TCGLLVMContextPrivate::getLabel(int idx)
{
    if(!m_labels[idx]) {
        std::ostringstream bbName;
        bbName << "label_" << idx;
        m_labels[idx] = BasicBlock::Create(m_context, bbName.str());
    }
    return m_labels[idx];
}

inline void TCGLLVMContextPrivate::delLabel(int idx)
{
    /* XXX
    if(m_labels[idx] && m_labels[idx]->use_empty() &&
            !m_labels[idx]->getParent())
        delete m_labels[idx];
    */
    m_labels[idx] = NULL;
}

void TCGLLVMContextPrivate::startNewBasicBlock(BasicBlock *bb)
{
    if(!bb)
        bb = BasicBlock::Create(m_context);
    else
        assert(bb->getParent() == 0);

    if(!m_builder.GetInsertBlock()->getTerminator())
        m_builder.CreateBr(bb);

    m_tbFunction->getBasicBlockList().push_back(bb);
    m_builder.SetInsertPoint(bb);

    /* Invalidate all temps */
    for(int i=0; i<TCG_MAX_TEMPS; ++i)
        delValue(i);

    /* Invalidate all pointers to globals */
    for(int i=0; i<m_tcgContext->nb_globals; ++i)
        delPtrForValue(i);

    m_registers.clear();
}

inline Value* TCGLLVMContextPrivate::generateCpuStatePtr(TCGArg registerOffset, unsigned sizeInBytes)
{
#if defined(USE_GEPS)
    SmallVector<Value*, 3> gepElements;
    if ((registerOffset % (TARGET_LONG_BITS / 8)) != 0) {
        return NULL;
    }

    //XXX: assumes x86
    static unsigned TARGET_LONG_BYTES = TARGET_LONG_BITS / 8;
    Value *ret = NULL;
    if ((registerOffset + sizeInBytes) <= m_tcgContext->env_offset_ccop) {
        unsigned reg = registerOffset / TARGET_LONG_BYTES;

        GepMap::iterator it = m_registers.find(registerOffset);
        if (it != m_registers.end()) {
            ret = (*it).second;
        } else {
            gepElements.push_back(ConstantInt::get(m_module->getContext(), APInt(32,  0)));
            gepElements.push_back(ConstantInt::get(m_module->getContext(), APInt(32,  0))); //register array
            gepElements.push_back(ConstantInt::get(m_module->getContext(), APInt(32,  reg)));
            ret = m_builder.CreateGEP(m_cpuState, ArrayRef<Value*>(gepElements.begin(), gepElements.end()));
            m_registers[registerOffset] = ret;
        }
    } else if ((registerOffset + sizeInBytes) <= m_tcgContext->env_offset_df) {
        if (registerOffset == m_tcgContext->env_offset_eip && m_eip) {
            ret = m_eip;
        } else if (registerOffset == m_tcgContext->env_offset_ccop && m_ccop) {
            ret = m_ccop;
        } else {
            GepMap::iterator it = m_registers.find(registerOffset);
            if (it != m_registers.end()) {
                ret = (*it).second;
            } else {
                unsigned reg = (registerOffset - m_tcgContext->env_offset_ccop) / TARGET_LONG_BYTES;
                gepElements.push_back(ConstantInt::get(m_module->getContext(), APInt(32,  0)));
                gepElements.push_back(ConstantInt::get(m_module->getContext(), APInt(32,  1 + reg)));
                ret = m_builder.CreateGEP(m_cpuState, ArrayRef<Value*>(gepElements.begin(), gepElements.end()));
                m_registers[registerOffset] = ret;
            }
        }
    }

    if (ret && sizeInBytes < TARGET_LONG_BYTES) {
        ret = m_builder.CreatePointerCast(ret, intPtrType(sizeInBytes * 8));
    }

    return ret;
#else
    return NULL;
#endif
}
#if 0
assert(getValue(args[1])->getType() == wordType());         \
v = m_builder.CreateAdd(getValue(args[1]),                  \
            ConstantInt::get(wordType(), args[2]));         \
v = m_builder.CreateIntToPtr(v, intPtrType(memBits));       \
v = m_builder.CreateLoad(v);                                \
setValue(args[0], m_builder.Create ## signE ## Ext(         \
            v, intType(regBits)));                          \

#endif

inline void TCGLLVMContextPrivate::generateQemuCpuLoad(const TCGArg *args, unsigned memBits, unsigned regBits, bool signExtend)
{
    assert(getValue(args[1])->getType() == wordType());
    assert(memBits <= regBits);
    Value *gep = generateCpuStatePtr(args[2], memBits / 8);
    Value *v;

    if (gep) {
        v = m_builder.CreateLoad(gep);
        v = m_builder.CreateTrunc(v, intType(memBits));
    } else {
        v = m_builder.CreateAdd(getValue(args[1]),
                    ConstantInt::get(wordType(), args[2]));
        v = m_builder.CreateIntToPtr(v, intPtrType(memBits));
        v = m_builder.CreateLoad(v);
    }

    if (signExtend) {
        setValue(args[0], m_builder.CreateSExt(v, intType(regBits)));
    } else {
        setValue(args[0], m_builder.CreateZExt(v, intType(regBits)));
    }
}

inline void TCGLLVMContextPrivate::generateQemuCpuStore(const TCGArg *args, unsigned memBits, Value *valueToStore)
{
    Value *gep = generateCpuStatePtr(args[2], memBits / 8);
    Value *v = NULL;
    if (gep) {
        v = m_builder.CreatePointerCast(gep, intType(memBits)->getPointerTo());
    } else {
        v = m_builder.CreateAdd(getValue(args[1]),
                    ConstantInt::get(wordType(), args[2]));
        v = m_builder.CreateIntToPtr(v, intPtrType(memBits));
    }

#ifdef STATIC_TRANSLATOR
    StoreInst *s = m_builder.CreateStore(m_builder.CreateTrunc(
                    valueToStore, intType(memBits)), v);
    if (isPcAssignment(gep)) {
        m_info.pcAssignments.push_back(s);
    }
#else
    m_builder.CreateStore(m_builder.CreateTrunc(
            valueToStore, intType(memBits)), v);
#endif
}

#if 0
    v = m_builder.CreateAdd(getValue(args[1]),                  \
                ConstantInt::get(wordType(), args[2]));         \
    v = m_builder.CreateIntToPtr(v, intPtrType(memBits));       \
    m_builder.CreateStore(m_builder.CreateTrunc(                \
            valueToStore, intType(memBits)), v);           \

#endif



inline Value* TCGLLVMContextPrivate::generateQemuMemOp(bool ld,
        Value *value, Value *addr, int mem_index, int bits)
{
    assert(addr->getType() == intType(TARGET_LONG_BITS));
    assert(ld || value->getType() == intType(bits));
    assert(TCG_TARGET_REG_BITS == 64); //XXX

#ifdef CONFIG_SOFTMMU

#if defined(CONFIG_SYMBEX)
    if(ld) {
        return attachCurrentPc(m_builder.CreateCall(m_qemu_ld_helpers[bits>>4],
                    {addr, ConstantInt::get(intType(8*sizeof(int)), mem_index)}));
    } else {
        attachCurrentPc(m_builder.CreateCall(m_qemu_st_helpers[bits>>4],
                    {addr, value, ConstantInt::get(intType(8*sizeof(int)), mem_index)}));
        return NULL;
    }
#endif
#else // CONFIG_SOFTMMU
    addr = m_builder.CreateZExt(addr, wordType());
    addr = m_builder.CreateAdd(addr,
        ConstantInt::get(wordType(), GUEST_BASE));
    addr = m_builder.CreateIntToPtr(addr, intPtrType(bits));
    if(ld) {
        return m_builder.CreateLoad(addr);
    } else {
        m_builder.CreateStore(value, addr);
        return NULL;
    }
#endif // CONFIG_SOFTMMU
}

void TCGLLVMContextPrivate::generateTraceCall(uintptr_t pc)
{
#ifdef CONFIG_SYMBEX
#if 0
    if (pc == 0x000f56e7 || pc == 0x000f52ff || pc == 0xf530c) {
         m_builder.CreateCall(m_helperTraceInstruction);
    }
#endif
#endif
}

int TCGLLVMContextPrivate::generateOperation(int opc, const TCGArg *args)
{
    Value *v = NULL;
    TCGOpDef &def = tcg_op_defs[opc];
    int nb_args = def.nb_args;

    switch(opc) {
    case INDEX_op_debug_insn_start:
        break;

    /* predefined ops */
    case INDEX_op_nop:
    case INDEX_op_nop1:
    case INDEX_op_nop2:
    case INDEX_op_nop3:
        break;

    case INDEX_op_nopn:
        nb_args = args[0];
        break;

    case INDEX_op_discard:
        delValue(args[0]);
        break;

    case INDEX_op_call:
        {
            int nb_oargs = args[0] >> 16;
            int nb_iargs = args[0] & 0xffff;
            nb_args = nb_oargs + nb_iargs + def.nb_cargs + 1;

            //int flags = args[nb_oargs + nb_iargs + 1];
            //assert((flags & TCG_CALL_TYPE_MASK) == TCG_CALL_TYPE_STD);

            std::vector<Value*> argValues;
            std::vector<Type*> argTypes;
            argValues.reserve(nb_iargs-1);
            argTypes.reserve(nb_iargs-1);
            for(int i=0; i < nb_iargs-1; ++i) {
                TCGArg arg = args[nb_oargs + i + 1];
                if(arg != TCG_CALL_DUMMY_ARG) {
                    Value *v = getValue(arg);
                    argValues.push_back(v);
                    argTypes.push_back(v->getType());
                }
            }

            assert(nb_oargs == 0 || nb_oargs == 1);
            Type* retType = nb_oargs == 0 ?
                Type::getVoidTy(m_context) : wordType(getValueBits(args[1]));

            Value* helperAddr = getValue(args[nb_oargs + nb_iargs]);
            Value* result;

            //Generate this in S2E mode
            tcg_target_ulong helperAddrC = (tcg_target_ulong)
                   cast<ConstantInt>(helperAddr)->getZExtValue();
            assert(helperAddrC);

            const char *helperName = tcg_helper_get_name(m_tcgContext,
                                                         (void*) helperAddrC);
            assert(helperName);

            std::string funcName = std::string("helper_") + helperName;
            Function* helperFunc = m_module->getFunction(funcName);
#ifndef STATIC_TRANSLATOR
            if(!helperFunc) {
                helperFunc = Function::Create(
                        FunctionType::get(retType, argTypes, false),
                        Function::ExternalLinkage, funcName, m_module);
                /* XXX: Why do we need this ? */
                sys::DynamicLibrary::AddSymbol(funcName, (void*) helperAddrC);
            }
#endif

            FunctionType *FTy =
               cast<FunctionType>(cast<PointerType>(helperFunc->getType())->getElementType());
            /**
             * Cast arguments to target function type.
             * Types may differ, e.g., when calling mmx functions.
             * XXX: why didn't this crash in S2E mode?
             */

            for (unsigned i = 0; i < FTy->getNumParams(); ++i) {
                if (FTy->getParamType(i) != argTypes[i]) {
                    if (FTy->getParamType(i)->isPointerTy()) {
                        argValues[i] = m_builder.CreateIntToPtr(argValues[i], FTy->getParamType(i));
                    } else {
                        assert(false && "Not supported cast");
                    }
                    //llvm::outs() << "Type differs:" << *FTy->getParamType(i) << " and " << *argTypes[i] << "\n";
                }
            }

            result = m_builder.CreateCall(helperFunc,
                                          ArrayRef<Value*>(argValues));


            /* Invalidate in-memory values because
             * function might have changed them */
            for(int i=0; i<m_tcgContext->nb_globals; ++i)
                delValue(i);

            for(int i=m_tcgContext->nb_globals; i<TCG_MAX_TEMPS; ++i)
                if(m_tcgContext->temps[i].temp_local)
                    delValue(i);

            /* Invalidate all pointers to globals */
            for(int i=0; i<m_tcgContext->nb_globals; ++i)
                delPtrForValue(i);

            if(nb_oargs == 1)
                setValue(args[1], result);
        }
        break;

    case INDEX_op_br:
        m_builder.CreateBr(getLabel(args[0]));
        startNewBasicBlock();
        break;

#define __OP_BRCOND_C(tcg_cond, cond)                               \
            case tcg_cond:                                          \
                v = m_builder.CreateICmp ## cond(                   \
                        getValue(args[0]), getValue(args[1]));      \
            break;

#define __OP_BRCOND(opc_name, bits)                                 \
    case opc_name: {                                                \
        assert(getValue(args[0])->getType() == intType(bits));      \
        assert(getValue(args[1])->getType() == intType(bits));      \
        switch(args[2]) {                                           \
            __OP_BRCOND_C(TCG_COND_EQ,   EQ)                        \
            __OP_BRCOND_C(TCG_COND_NE,   NE)                        \
            __OP_BRCOND_C(TCG_COND_LT,  SLT)                        \
            __OP_BRCOND_C(TCG_COND_GE,  SGE)                        \
            __OP_BRCOND_C(TCG_COND_LE,  SLE)                        \
            __OP_BRCOND_C(TCG_COND_GT,  SGT)                        \
            __OP_BRCOND_C(TCG_COND_LTU, ULT)                        \
            __OP_BRCOND_C(TCG_COND_GEU, UGE)                        \
            __OP_BRCOND_C(TCG_COND_LEU, ULE)                        \
            __OP_BRCOND_C(TCG_COND_GTU, UGT)                        \
            default:                                                \
                tcg_abort();                                        \
        }                                                           \
        BasicBlock* bb = BasicBlock::Create(m_context);             \
        m_builder.CreateCondBr(v, getLabel(args[3]), bb);           \
        startNewBasicBlock(bb);                                     \
    } break;

    __OP_BRCOND(INDEX_op_brcond_i32, 32)

#if TCG_TARGET_REG_BITS == 64
    __OP_BRCOND(INDEX_op_brcond_i64, 64)
#endif

#undef __OP_BRCOND_C
#undef __OP_BRCOND

    case INDEX_op_set_label:
        assert(getLabel(args[0])->getParent() == 0);
        startNewBasicBlock(getLabel(args[0]));
        break;

    case INDEX_op_movi_i32:
        setValue(args[0], ConstantInt::get(intType(32), args[1]));
        break;

    case INDEX_op_mov_i32:
        // Move operation may perform truncation of the value
        assert(getValue(args[1])->getType() == intType(32) ||
                getValue(args[1])->getType() == intType(64));
        setValue(args[0],
                m_builder.CreateTrunc(getValue(args[1]), intType(32)));
        break;

#if TCG_TARGET_REG_BITS == 64
    case INDEX_op_movi_i64:
        setValue(args[0], ConstantInt::get(intType(64), args[1]));
        break;

    case INDEX_op_mov_i64:
        assert(getValue(args[1])->getType() == intType(64));
        setValue(args[0], getValue(args[1]));
        break;
#endif

    /* size extensions */
#define __EXT_OP(opc_name, truncBits, opBits, signE )               \
    case opc_name:                                                  \
        /*                                                          \
        assert(getValue(args[1])->getType() == intType(opBits) ||   \
               getValue(args[1])->getType() == intType(truncBits)); \
        */                                                          \
        setValue(args[0], m_builder.Create ## signE ## Ext(         \
                m_builder.CreateTrunc(                              \
                    getValue(args[1]), intType(truncBits)),         \
                intType(opBits)));                                  \
        break;

    __EXT_OP(INDEX_op_ext8s_i32,   8, 32, S)
    __EXT_OP(INDEX_op_ext8u_i32,   8, 32, Z)
    __EXT_OP(INDEX_op_ext16s_i32, 16, 32, S)
    __EXT_OP(INDEX_op_ext16u_i32, 16, 32, Z)

#if TCG_TARGET_REG_BITS == 64
    __EXT_OP(INDEX_op_ext8s_i64,   8, 64, S)
    __EXT_OP(INDEX_op_ext8u_i64,   8, 64, Z)
    __EXT_OP(INDEX_op_ext16s_i64, 16, 64, S)
    __EXT_OP(INDEX_op_ext16u_i64, 16, 64, Z)
    __EXT_OP(INDEX_op_ext32s_i64, 32, 64, S)
    __EXT_OP(INDEX_op_ext32u_i64, 32, 64, Z)
#endif

#undef __EXT_OP

#if 0
    /* load/store */
#define __LD_OP(opc_name, memBits, regBits, signE)                  \
    case opc_name:                                                  \
        assert(getValue(args[1])->getType() == wordType());         \
        v = m_builder.CreateAdd(getValue(args[1]),                  \
                    ConstantInt::get(wordType(), args[2]));         \
        v = m_builder.CreateIntToPtr(v, intPtrType(memBits));       \
        v = m_builder.CreateLoad(v);                                \
        setValue(args[0], m_builder.Create ## signE ## Ext(         \
                    v, intType(regBits)));                          \
        break;
#endif

#define __LD_OP(opc_name, memBits, regBits, signE) \
    case opc_name: \
        generateQemuCpuLoad(args, memBits, regBits, signE == 'S'); \
        break;

#define __ST_OP(opc_name, memBits, regBits)                         \
    case opc_name:  {                                               \
        assert(getValue(args[0])->getType() == intType(regBits));   \
        assert(getValue(args[1])->getType() == wordType());         \
        Value* valueToStore = getValue(args[0]);                    \
                                                                    \
        if (TARGET_LONG_BITS == memBits                             \
            && args[1] == 0                                         \
            && args[2] == m_tcgContext->env_offset_eip) {           \
            valueToStore = handleSymbolicPcAssignment(valueToStore);\
        }                                                           \
                                                                    \
        generateQemuCpuStore(args, memBits, valueToStore);          \
    } break;

    __LD_OP(INDEX_op_ld8u_i32,   8, 32, 'Z')
    __LD_OP(INDEX_op_ld8s_i32,   8, 32, 'S')
    __LD_OP(INDEX_op_ld16u_i32, 16, 32, 'Z')
    __LD_OP(INDEX_op_ld16s_i32, 16, 32, 'S')
    __LD_OP(INDEX_op_ld_i32,    32, 32, 'Z')

    __ST_OP(INDEX_op_st8_i32,   8, 32)
    __ST_OP(INDEX_op_st16_i32, 16, 32)
    __ST_OP(INDEX_op_st_i32,   32, 32)

#if TCG_TARGET_REG_BITS == 64
    __LD_OP(INDEX_op_ld8u_i64,   8, 64, 'Z')
    __LD_OP(INDEX_op_ld8s_i64,   8, 64, 'S')
    __LD_OP(INDEX_op_ld16u_i64, 16, 64, 'Z')
    __LD_OP(INDEX_op_ld16s_i64, 16, 64, 'S')
    __LD_OP(INDEX_op_ld32u_i64, 32, 64, 'Z')
    __LD_OP(INDEX_op_ld32s_i64, 32, 64, 'S')
    __LD_OP(INDEX_op_ld_i64,    64, 64, 'Z')

    __ST_OP(INDEX_op_st8_i64,   8, 64)
    __ST_OP(INDEX_op_st16_i64, 16, 64)
    __ST_OP(INDEX_op_st32_i64, 32, 64)
    __ST_OP(INDEX_op_st_i64,   64, 64)
#endif

#undef __LD_OP
#undef __ST_OP

    /* arith */
#define __ARITH_OP(opc_name, op, bits)                              \
    case opc_name: {                                                \
        Value *v1 = getValue(args[1]);                              \
        Value *v2 = getValue(args[2]);                              \
        adjustTypeSize(bits, &v1, &v2);                             \
        assert(v1->getType() == intType(bits));                     \
        assert(v2->getType() == intType(bits));                     \
        setValue(args[0], m_builder.Create ## op(v1, v2));          \
    } break;

#define __ARITH_OP_DIV2(opc_name, signE, bits)                      \
    case opc_name:                                                  \
        assert(getValue(args[2])->getType() == intType(bits));      \
        assert(getValue(args[3])->getType() == intType(bits));      \
        assert(getValue(args[4])->getType() == intType(bits));      \
        v = m_builder.CreateShl(                                    \
                m_builder.CreateZExt(                               \
                    getValue(args[3]), intType(bits*2)),            \
                m_builder.CreateZExt(                               \
                    ConstantInt::get(intType(bits), bits),          \
                    intType(bits*2)));                              \
        v = m_builder.CreateOr(v,                                   \
                m_builder.CreateZExt(                               \
                    getValue(args[2]), intType(bits*2)));           \
        setValue(args[0], m_builder.Create ## signE ## Div(         \
                v, getValue(args[4])));                             \
        setValue(args[1], m_builder.Create ## signE ## Rem(         \
                v, getValue(args[4])));                             \
        break;

#define __ARITH_OP_ROT(opc_name, op1, op2, bits)                    \
    case opc_name:                                                  \
        assert(getValue(args[1])->getType() == intType(bits));      \
        assert(getValue(args[2])->getType() == intType(bits));      \
        v = m_builder.CreateSub(                                    \
                ConstantInt::get(intType(bits), bits),              \
                getValue(args[2]));                                 \
        setValue(args[0], m_builder.CreateOr(                       \
                m_builder.Create ## op1 (                           \
                    getValue(args[1]), getValue(args[2])),          \
                m_builder.Create ## op2 (                           \
                    getValue(args[1]), v)));                        \
        break;

#define __ARITH_OP_I(opc_name, op, i, bits)                         \
    case opc_name:                                                  \
        assert(getValue(args[1])->getType() == intType(bits));      \
        setValue(args[0], m_builder.Create ## op(                   \
                    ConstantInt::get(intType(bits), i),             \
                    getValue(args[1])));                            \
        break;

#define __ARITH_OP_BSWAP(opc_name, sBits, bits)                     \
    case opc_name: {                                                \
        assert(getValue(args[1])->getType() == intType(bits));      \
        Type* Tys[] = { intType(sBits) };                     \
        Function *bswap = Intrinsic::getDeclaration(m_module,       \
                Intrinsic::bswap, ArrayRef<Type*>(Tys,1));                          \
        v = m_builder.CreateTrunc(getValue(args[1]),intType(sBits));\
        setValue(args[0], m_builder.CreateZExt(                     \
                m_builder.CreateCall(bswap, v), intType(bits)));    \
        } break;


    __ARITH_OP(INDEX_op_add_i32, Add, 32)
    __ARITH_OP(INDEX_op_sub_i32, Sub, 32)
    __ARITH_OP(INDEX_op_mul_i32, Mul, 32)

#ifdef TCG_TARGET_HAS_div_i32
    __ARITH_OP(INDEX_op_div_i32,  SDiv, 32)
    __ARITH_OP(INDEX_op_divu_i32, UDiv, 32)
    __ARITH_OP(INDEX_op_rem_i32,  SRem, 32)
    __ARITH_OP(INDEX_op_remu_i32, URem, 32)
#else
    __ARITH_OP_DIV2(INDEX_op_div2_i32,  S, 32)
    __ARITH_OP_DIV2(INDEX_op_divu2_i32, U, 32)
#endif

    __ARITH_OP(INDEX_op_and_i32, And, 32)
    __ARITH_OP(INDEX_op_or_i32,   Or, 32)
    __ARITH_OP(INDEX_op_xor_i32, Xor, 32)

    __ARITH_OP(INDEX_op_shl_i32,  Shl, 32)
    __ARITH_OP(INDEX_op_shr_i32, LShr, 32)
    __ARITH_OP(INDEX_op_sar_i32, AShr, 32)

    __ARITH_OP_ROT(INDEX_op_rotl_i32, Shl, LShr, 32)
    __ARITH_OP_ROT(INDEX_op_rotr_i32, LShr, Shl, 32)

    __ARITH_OP_I(INDEX_op_not_i32, Xor, (uint64_t) -1, 32)
    __ARITH_OP_I(INDEX_op_neg_i32, Sub, 0, 32)

    __ARITH_OP_BSWAP(INDEX_op_bswap16_i32, 16, 32)
    __ARITH_OP_BSWAP(INDEX_op_bswap32_i32, 32, 32)

#if TCG_TARGET_REG_BITS == 64
    __ARITH_OP(INDEX_op_add_i64, Add, 64)
    __ARITH_OP(INDEX_op_sub_i64, Sub, 64)
    __ARITH_OP(INDEX_op_mul_i64, Mul, 64)

#ifdef TCG_TARGET_HAS_div_i64
    __ARITH_OP(INDEX_op_div_i64,  SDiv, 64)
    __ARITH_OP(INDEX_op_divu_i64, UDiv, 64)
    __ARITH_OP(INDEX_op_rem_i64,  SRem, 64)
    __ARITH_OP(INDEX_op_remu_i64, URem, 64)
#else
    __ARITH_OP_DIV2(INDEX_op_div2_i64,  S, 64)
    __ARITH_OP_DIV2(INDEX_op_divu2_i64, U, 64)
#endif

    __ARITH_OP(INDEX_op_and_i64, And, 64)
    __ARITH_OP(INDEX_op_or_i64,   Or, 64)
    __ARITH_OP(INDEX_op_xor_i64, Xor, 64)

    __ARITH_OP(INDEX_op_shl_i64,  Shl, 64)
    __ARITH_OP(INDEX_op_shr_i64, LShr, 64)
    __ARITH_OP(INDEX_op_sar_i64, AShr, 64)

    __ARITH_OP_ROT(INDEX_op_rotl_i64, Shl, LShr, 64)
    __ARITH_OP_ROT(INDEX_op_rotr_i64, LShr, Shl, 64)

    __ARITH_OP_I(INDEX_op_not_i64, Xor, (uint64_t) -1, 64)
    __ARITH_OP_I(INDEX_op_neg_i64, Sub, 0, 64)

    __ARITH_OP_BSWAP(INDEX_op_bswap16_i64, 16, 64)
    __ARITH_OP_BSWAP(INDEX_op_bswap32_i64, 32, 64)
    __ARITH_OP_BSWAP(INDEX_op_bswap64_i64, 64, 64)
#endif

#undef __ARITH_OP_BSWAP
#undef __ARITH_OP_I
#undef __ARITH_OP_ROT
#undef __ARITH_OP_DIV2
#undef __ARITH_OP

    /* QEMU specific */
#if TCG_TARGET_REG_BITS == 64

#define __OP_QEMU_ST(opc_name, bits)                                \
    case opc_name:                                                  \
        generateQemuMemOp(false,                                    \
            m_builder.CreateIntCast(                                \
                getValue(args[0]), intType(bits), false),           \
            getValue(args[1]), args[2], bits);                      \
        break;


#define __OP_QEMU_LD(opc_name, bits, signE)                         \
    case opc_name:                                                  \
        v = generateQemuMemOp(true, NULL,                           \
            getValue(args[1]), args[2], bits);                      \
        setValue(args[0], m_builder.Create ## signE ## Ext(         \
            v, intType(std::max(TARGET_LONG_BITS, bits))));         \
        break;

#define __OP_QEMU_LDD(opc_name, bits)                               \
    case opc_name:                                                  \
        v = generateQemuMemOp(true, NULL,                           \
            getValue(args[1]), args[2], bits);                      \
        setValue(args[0], v);         \
        break;

    __OP_QEMU_ST(INDEX_op_qemu_st8,   8)
    __OP_QEMU_ST(INDEX_op_qemu_st16, 16)
    __OP_QEMU_ST(INDEX_op_qemu_st32, 32)
    __OP_QEMU_ST(INDEX_op_qemu_st64, 64)

    __OP_QEMU_LD(INDEX_op_qemu_ld8s,   8, S)
    __OP_QEMU_LD(INDEX_op_qemu_ld8u,   8, Z)
    __OP_QEMU_LD(INDEX_op_qemu_ld16s, 16, S)
    __OP_QEMU_LD(INDEX_op_qemu_ld16u, 16, Z)
    __OP_QEMU_LD(INDEX_op_qemu_ld32s, 32, S)
    __OP_QEMU_LD(INDEX_op_qemu_ld32u, 32, Z)
    __OP_QEMU_LD(INDEX_op_qemu_ld64,  64, Z)

    __OP_QEMU_LDD(INDEX_op_qemu_ld32, 32)

#undef __OP_QEMU_LD
#undef __OP_QEMU_ST
#undef __OP_QEMU_LDD

#endif

    case INDEX_op_exit_tb: {
#ifdef STATIC_TRANSLATOR
        ReturnInst *ret = m_builder.CreateRet(ConstantInt::get(wordType(), args[0]));
        m_info.returnInstructions.push_back(ret);
#else
        m_builder.CreateRet(ConstantInt::get(wordType(), args[0]));
#endif
    } break;

    case INDEX_op_goto_tb:
#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
        m_builder.CreateStore(ConstantInt::get(intType(8), args[0]),
                m_builder.CreateIntToPtr(ConstantInt::get(wordType(),
                    (uint64_t) &tcg_llvm_runtime.goto_tb),
                intPtrType(8)));
#endif
        /* XXX: tb linking is disabled */
        break;

    case INDEX_op_deposit_i32: {
        //llvm::errs() << *m_tbFunction << "\n";
        Value *arg1 = getValue(args[1]);
        //llvm::errs() << "arg1=" << *arg1 << "\n";
        //arg1 = m_builder.CreateTrunc(arg1, intType(32));


        Value *arg2 = getValue(args[2]);
        //llvm::errs() << "arg2=" << *arg2 << "\n";
        arg2 = m_builder.CreateTrunc(arg2, intType(32));

        uint32_t ofs = args[3];
        uint32_t len = args[4];

        if (ofs == 0 && len == 32) {
            setValue(args[0], arg2);
            break;
        }

        uint32_t mask = (1u << len) - 1;
        Value *t1, *ret;
        if (ofs + len < 32) {
            t1 = m_builder.CreateAnd(arg2, APInt(32, mask));
            t1 = m_builder.CreateShl(t1, APInt(32, ofs));
        } else {
            t1 = m_builder.CreateShl(arg2, APInt(32, ofs));
        }

        ret = m_builder.CreateAnd(arg1, APInt(32, ~(mask << ofs)));
        ret = m_builder.CreateOr(ret, t1);
        setValue(args[0], ret);
    }
    break;
#if TCG_TARGET_REG_BITS == 64
    case INDEX_op_deposit_i64: {
        Value *arg1 = getValue(args[1]);
        Value *arg2 = getValue(args[2]);
        arg2 = m_builder.CreateTrunc(arg2, intType(64));

        uint32_t ofs = args[3];
        uint32_t len = args[4];

        if (0 == ofs && 64 == len) {
            setValue(args[0], arg2);
            break;
        }

        uint64_t mask = (1u << len) - 1;
        Value *t1, *ret;

        if (ofs + len < 64) {
            t1 = m_builder.CreateAnd(arg2, APInt(64, mask));
            t1 = m_builder.CreateShl(t1, APInt(64, ofs));
        } else {
            t1 = m_builder.CreateShl(arg2, APInt(64, ofs));
        }

        ret = m_builder.CreateAnd(arg1, APInt(64, ~(mask << ofs)));
        ret = m_builder.CreateOr(ret, t1);
        setValue(args[0], ret);
    }
    break;
#endif

    default:
        std::cerr << "ERROR: unknown TCG micro operation '"
                  << def.name << "'" << std::endl;
        tcg_abort();
        break;
    }

    return nb_args;
}

bool TCGLLVMContextPrivate::isInstrumented(llvm::Function *tb)
{
    std::string name = tb->getName();
    return name.find("insttb") != std::string::npos;
}

std::string TCGLLVMContextPrivate::generateName()
{
    std::ostringstream fName;

#ifdef CONFIG_SYMBEX
    if (m_tcgContext->tb_instrumented) {
        /* Instrumented TBs cannot be cached or made persistent */
        fName << "tcg-llvm-insttb-" << m_tbCount++ << "-"
                << std::hex << m_tcgContext->tb_pc;
    } else {
        /* Create new function for current translation block */
        /* XXX: compute the checksum of the tb to be fully  */
        fName << "tcg-llvm-tb-" << std::hex
                << m_tcgContext->tb_pc << '-'
                << m_tcgContext->tb_size << '-'
                //The size of the generated TB is important to avoid collisions
                << m_tcgContext->tb_tc_size << '-'
                << m_tcgContext->tb_cs_base << '-' << m_tcgContext->tb_flags;
    }
#else
    fName << "tcg-llvm-insttb-" << m_tbCount++ << "-"
            << std::hex << tb->pc;
#endif

    return fName.str();
}

Function *TCGLLVMContextPrivate::createTbFunction(const std::string &name)
{
    FunctionType *tbFunctionType = tbType();

    return Function::Create(tbFunctionType,
            Function::ExternalLinkage, name, m_module);
}

Function *TCGLLVMContextPrivate::generateCode(TCGContext *s)
{
#ifdef CONFIG_SYMBEX
    tb_precise_pc_t *p = s->precise_pcs;
    tb_precise_pc_t *max_p = s->precise_pcs + s->precise_entries;

    //First instruction(s) can be nop, so the first entry's pc
    //does not always match tb's pc.
    //assert(p->guest_pc == tb->pc);
#endif

#ifdef STATIC_TRANSLATOR
    m_info.clear();
#endif

    m_tcgContext = s;

    std::string name = generateName();

    m_registers.clear();

    Function *existingTb = m_module->getFunction(name);
    if (existingTb) {
        return existingTb;
    }

    m_tbFunction = createTbFunction(name);
    m_tbFunction->addFnAttr(Attribute::AlwaysInline);

    BasicBlock *basicBlock = BasicBlock::Create(m_context,
            "entry", m_tbFunction);
    m_builder.SetInsertPoint(basicBlock);

    /* Prepare globals and temps information */
    initGlobalsAndLocalTemps();

#if defined(USE_GEPS)
    loadNativeCpuState(m_tbFunction);
#endif

    /* Generate code for each opc */
    const TCGArg *args = gen_opparam_buf;
    for(int opc_index=0; ;++opc_index) {
        int opc = gen_opc_buf[opc_index];

        if(opc == INDEX_op_end)
            break;

#ifdef STATIC_TRANSLATOR
        if (p < max_p) {
            if (p->opc == opc_index) {
                m_currentPc = m_tcgContext->tb_pc + p->guest_pc_increment - m_tcgContext->tb_cs_base;
                ++p;
            }
        }


#elif defined(CONFIG_SYMBEX)
        if (p < max_p) {
            if (p->opc == opc_index) {
                /* Generate precise PC update */
                uint64_t curpc = m_tcgContext->tb_pc + p->guest_pc_increment - m_tcgContext->tb_cs_base;
                Value *valueToStore = handleSymbolicPcAssignment(ConstantInt::get(wordType(), curpc));

#if defined(USE_GEPS)
                TCGArg args[3];
                args[2] = m_tcgContext->env_offset_eip;
                generateQemuCpuStore(args, m_tcgContext->env_sizeof_eip * 8, valueToStore);
#else
                Value *ptr = m_builder.CreateAdd(getValue(0),
                            ConstantInt::get(wordType(), m_tcgContext->env_offset_eip));

                ptr = m_builder.CreateIntToPtr(ptr, intPtrType(m_tcgContext->env_sizeof_eip * 8));
                m_builder.CreateStore(m_builder.CreateTrunc(
                        valueToStore, intType(m_tcgContext->env_sizeof_eip * 8)), ptr);
#endif

                if (p->cc_op != CC_OP_DYNAMIC) {
#if defined(USE_GEPS)
                    args[2] = m_tcgContext->env_offset_ccop;
                    valueToStore = ConstantInt::get(wordType(m_tcgContext->env_sizeof_ccop * 8), p->cc_op);
                    generateQemuCpuStore(args, m_tcgContext->env_sizeof_ccop * 8, valueToStore);

#else
                    valueToStore = ConstantInt::get(wordType(m_tcgContext->env_sizeof_ccop * 8), p->cc_op);
                    Value *ptr = m_builder.CreateAdd(getValue(0),
                                ConstantInt::get(wordType(), m_tcgContext->env_offset_ccop));

                    ptr = m_builder.CreateIntToPtr(ptr, intPtrType(m_tcgContext->env_sizeof_ccop * 8));
                    m_builder.CreateStore(m_builder.CreateTrunc(
                            valueToStore, intType(m_tcgContext->env_sizeof_ccop * 8)), ptr);
#endif
                }
                ++p;
            }
        }
#endif
        if(opc == INDEX_op_debug_insn_start) {
#ifndef CONFIG_SYMBEX
            // volatile store of current OPC index
            m_builder.CreateStore(ConstantInt::get(wordType(), opc_index),
                m_builder.CreateIntToPtr(
                    ConstantInt::get(wordType(),
                        (uint64_t) &tcg_llvm_runtime.last_opc_index),
                    wordPtrType()),
                true);
            // volatile store of current PC
            m_builder.CreateStore(ConstantInt::get(wordType(), args[0]),
                m_builder.CreateIntToPtr(
                    ConstantInt::get(wordType(),
                        (uint64_t) &tcg_llvm_runtime.last_pc),
                    wordPtrType()),
                true);
#endif
        }

        generateTraceCall(m_tcgContext->tb_pc);
        args += generateOperation(opc, args);
        //llvm::outs() << *m_tbFunction << "\n";
    }

    /* Finalize function */
    if(!isa<ReturnInst>(m_tbFunction->back().back())) {
#ifdef STATIC_TRANSLATOR
        ReturnInst *ret = m_builder.CreateRet(ConstantInt::get(wordType(), 0));
        m_info.returnInstructions.push_back(ret);
#else
        m_builder.CreateRet(ConstantInt::get(wordType(), 0));
#endif
    }

    /* Clean up unused m_values */
    for(int i=0; i<TCG_MAX_TEMPS; ++i)
        delValue(i);

    /* Delete pointers after deleting values */
    for(int i=0; i<TCG_MAX_TEMPS; ++i)
        delPtrForValue(i);

    for(int i=0; i<TCG_MAX_LABELS; ++i)
        delLabel(i);

#ifndef NDEBUG
    if (verifyFunction(*m_tbFunction)) {
        std::error_code error;
        std::stringstream ss;
        ss << "llvm-"  << getpid() << ".log";
        llvm::raw_fd_ostream os(ss.str(), error, llvm::sys::fs::F_None);
        os << "Dumping function:\n";
        os.flush();
        os << *m_tbFunction << "\n";
        os.close();
        abort();
    }
#endif

#ifdef STATIC_TRANSLATOR
    computeStaticBranchTargets();
#endif

    //KLEE will optimize the function later
    //m_functionPassManager->run(*m_tbFunction);

    //XXX: implement proper logging
#if 0
    if(libcpu_loglevel_mask(CPU_LOG_LLVM_IR)) {
        std::string fcnString;
        llvm::raw_string_ostream s(fcnString);
        s << *m_tbFunction;
        libcpu_log("OUT (LLVM IR):\n");
        libcpu_log("%s", s.str().c_str());
        libcpu_log("\n");
        libcpu_log_flush();
    }
#endif

    return m_tbFunction;
}

#ifdef STATIC_TRANSLATOR
void TCGLLVMContextPrivate::computeStaticBranchTargets()
{
    unsigned sz = m_info.returnInstructions.size();

    //Simple case, only one assignment
    if (sz == 1) {
        StoreInst *si = m_info.pcAssignments.back();
        ConstantInt *ci = dynamic_cast<ConstantInt*>(si->getValueOperand());
        if (ci) {
            m_info.staticBranchTargets.push_back(ci->getZExtValue());
        }
    } else if (sz == 2) {
        unsigned asz = m_info.pcAssignments.size();

        //Figure out which is the true branch, which is the false one.
        //Pick the last 2 pc assignments
        StoreInst *s1 = m_info.pcAssignments[asz - 2];
        ConstantInt *c1 = dynamic_cast<ConstantInt*>(s1->getValueOperand());

        StoreInst *s2 = m_info.pcAssignments[asz - 1];
        ConstantInt *c2 = dynamic_cast<ConstantInt*>(s2->getValueOperand());

        if (!(c1 && c2)) {
            return;
        }

        BasicBlock *bb1 = s1->getParent();
        BasicBlock *p1 = bb1->getSinglePredecessor();
        BasicBlock *bb2 = s2->getParent();
        BasicBlock *p2 = bb2->getSinglePredecessor();

        /* Handle chain of direct branch */
        if (p1 && p1->size() == 1) {
            BasicBlock *sp = p1->getSinglePredecessor();
            if (sp) {
                p1 = sp;
            }
        }

        if (p2 && p2->size() == 1) {
            BasicBlock *sp = p2->getSinglePredecessor();
            if (sp) {
                p2 = sp;
            }
        }

        if (p1 && p1 == p2) {
            llvm::BranchInst *Bi = dynamic_cast<llvm::BranchInst*>(p1->getTerminator());
            if (Bi) {
                m_info.staticBranchTargets.resize(2);
                m_info.staticBranchTargets[0] = Bi->getSuccessor(0) == bb1 ? c1->getZExtValue() : c2->getZExtValue();
                m_info.staticBranchTargets[1] = Bi->getSuccessor(1) == bb2 ? c2->getZExtValue() : c1->getZExtValue();
            }
        }
    }

#if 0
    for (unsigned i = 0; i < m_info.returnInstructions.size(); ++i) {
        llvm::outs() << *m_info.returnInstructions[i]  << "\n";
    }

    for (unsigned i = 0; i < m_info.pcAssignments.size(); ++i) {
        llvm::outs() << *m_info.pcAssignments[i]  << "\n";
    }

    for (unsigned i = 0; i < m_info.staticBranchTargets.size(); ++i) {
        llvm::outs() << m_info.staticBranchTargets[i] << "\n";
    }
#endif
}

#endif

/***********************************/
/* External interface for C++ code */

TCGLLVMContext::TCGLLVMContext(LLVMContext& context)
        : m_private(new TCGLLVMContextPrivate(context))
{
}

TCGLLVMContext::~TCGLLVMContext()
{
    delete m_private;
}

llvm::legacy::FunctionPassManager* TCGLLVMContext::getFunctionPassManager() const
{
    return m_private->getFunctionPassManager();
}

LLVMContext& TCGLLVMContext::getLLVMContext()
{
    return m_private->m_context;
}

Module* TCGLLVMContext::getModule()
{
    return m_private->m_module;
}

#ifdef CONFIG_SYMBEX
void TCGLLVMContext::initializeHelpers()
{
    return m_private->initializeHelpers();
}

void TCGLLVMContext::initializeNativeCpuState()
{
    return m_private->initializeNativeCpuState();
}

bool TCGLLVMContext::isInstrumented(llvm::Function *tb)
{
    return m_private->isInstrumented(tb);
}
#endif

#ifdef STATIC_TRANSLATOR
const TCGLLVMTBInfo &TCGLLVMContext::getTbInfo() const
{
    return m_private->getTbInfo();
}

Function *TCGLLVMContext::createTbFunction(const std::string &name)
{
    return m_private->createTbFunction(name);
}

FunctionType *TCGLLVMContext::getTbType()
{
    return m_private->tbType();
}

#endif

Function* TCGLLVMContext::generateCode(TCGContext *s)
{
    return m_private->generateCode(s);
}

bool TCGLLVMContext::GetStaticBranchTarget(const llvm::BasicBlock *BB, uint64_t *target)
{
    if (!isa<llvm::ReturnInst>(BB->getTerminator())) {
        return false;
    }

    BasicBlock::const_iterator iit;
    for (iit = BB->begin(); iit != BB->end(); ++iit) {
        const llvm::StoreInst *store = dyn_cast<llvm::StoreInst>(iit);
        if (!store) {
            continue;
        }

        const llvm::ConstantInt *pc = dyn_cast<llvm::ConstantInt>(store->getValueOperand());
        if (!pc || pc->getBitWidth() != sizeof(target_ulong) * 8) {
            continue;
        }

        const llvm::GetElementPtrInst *gep = dyn_cast<llvm::GetElementPtrInst>(store->getPointerOperand());
        if (!gep) {
            continue;
        }

        if (gep->getNumOperands() != 3) {
            continue;
        }

        const llvm::ConstantInt *go1 = dyn_cast<llvm::ConstantInt>(gep->getOperand(1));
        const llvm::ConstantInt *go2 = dyn_cast<llvm::ConstantInt>(gep->getOperand(2));
        if (!go1 || !go2) {
            continue;
        }

        //XXX: hard-coded pc index
        if (!go1->isZero() || go2->getZExtValue() != 5) {
            continue;
        }

        *target = pc->getZExtValue();
        return true;
    }

    return false;
}

/*****************************/
/* Functions for QEMU c code */

#include <llvm-c/Core.h>

TCGLLVMContext* tcg_llvm_initialize()
{
    if (!llvm_is_multithreaded()) {
        fprintf(stderr, "Could not initialize LLVM threading\n");
        exit(-1);
    }

    LLVMContextRef contextRef = LLVMGetGlobalContext();

    return new TCGLLVMContext(*unwrap(contextRef));
}

void tcg_llvm_close(TCGLLVMContext *l)
{
    delete l;
}

void* tcg_llvm_gen_code(TCGLLVMContext *l, TCGContext *s)
{
    return l->generateCode(s);
}
