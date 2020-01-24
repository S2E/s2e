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

// Enforce include order
// clang-format off
extern "C" {
#include <tcg/tcg.h>
#include <tcg/tb.h>
}
// clang-format on

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
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Scalar/GVN.h>
#include <llvm/Transforms/Utils.h>
#include <llvm/Bitcode/BitcodeReader.h>

#include <llvm/Support/DynamicLibrary.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/raw_ostream.h>

#include <llvm/ADT/DenseMap.h>
#include <llvm-c/Core.h>

#include <iostream>
#include <sstream>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>

#if TARGET_LONG_BITS == 32
typedef uint32_t target_ulong;
#else
typedef uint64_t target_ulong;
#endif

// XXX: hack
#define CC_OP_DYNAMIC 0

extern "C" {
// TODO: get rid of this global var
void *tcg_llvm_translator = 0;
}

using namespace llvm;

unsigned TCGLLVMTranslator::m_eip_last_gep_index = 0;

TCGLLVMTranslator::TCGLLVMTranslator(const std::string &bitcodeLibraryPath, std::unique_ptr<Module> module)
    : m_bitcodeLibraryPath(bitcodeLibraryPath), m_module(std::move(module)), m_builder(m_module->getContext()),
      m_tbCount(0), m_tcgContext(NULL), m_tbFunction(NULL), m_tbType(NULL) {
    std::memset(m_values, 0, sizeof(m_values));
    std::memset(m_memValuesPtr, 0, sizeof(m_memValuesPtr));
    std::memset(m_globalsIdx, 0, sizeof(m_globalsIdx));

    m_functionPassManager = new legacy::FunctionPassManager(m_module.get());
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

    initializeNativeCpuState();
    initializeHelpers();
}

TCGLLVMTranslator *TCGLLVMTranslator::create(const std::string &bitcodeLibraryPath) {
    if (!llvm_is_multithreaded()) {
        fprintf(stderr, "Could not initialize LLVM threading\n");
        exit(-1);
    }

    auto ctx = unwrap(LLVMGetGlobalContext());

    // Read the helper bitcode file
    auto ErrorOrMemBuff = MemoryBuffer::getFile(bitcodeLibraryPath);
    if (std::error_code EC = ErrorOrMemBuff.getError()) {
        llvm::errs() << "Reading " << bitcodeLibraryPath << " failed!\n";
        return nullptr;
    }

    auto ErrorOrMod = parseBitcodeFile(ErrorOrMemBuff.get()->getMemBufferRef(), *ctx);
    if (!ErrorOrMod) {
        return nullptr;
    }

    auto ret = new TCGLLVMTranslator(bitcodeLibraryPath, std::move(ErrorOrMod.get()));

    tcg_llvm_translator = ret;
    return ret;
}

TCGLLVMTranslator::~TCGLLVMTranslator() {
    delete m_functionPassManager;
}

llvm::FunctionType *TCGLLVMTranslator::tbType() {
    if (m_tbType) {
        return m_tbType;
    }
    llvm::SmallVector<Type *, 1> args;
    args.push_back(m_cpuType->getPointerTo());
    m_tbType = llvm::FunctionType::get(wordType(), args, false);
    return m_tbType;
}

void TCGLLVMTranslator::adjustTypeSize(unsigned target, llvm::Value **v1) {
    Value *va = *v1;
    if (target == 32) {
        if (va->getType() == intType(64)) {
            *v1 = m_builder.CreateTrunc(va, intType(target));
        } else if (va->getType() != intType(32)) {
            assert(false);
        }
    }
}

llvm::Value *TCGLLVMTranslator::handleSymbolicPcAssignment(llvm::Value *orig) {
#if defined(CONFIG_SYMBEX) && !defined(STATIC_TRANSLATOR)
    if (isa<ConstantInt>(orig)) {
        return orig;
    }
    std::vector<Value *> argValues;
    Type *t = intType(TARGET_LONG_BITS);
    argValues.push_back(orig);
    argValues.push_back(ConstantInt::get(t, 0));
    argValues.push_back(ConstantInt::get(t, (target_ulong) -1));
    argValues.push_back(ConstantInt::get(t, 1));
    Value *valueToStore = m_builder.CreateCall(m_helperForkAndConcretize, ArrayRef<Value *>(argValues));

    valueToStore = m_builder.CreateTrunc(valueToStore, intType(TARGET_LONG_BITS));
    return valueToStore;
#else
    return orig;
#endif
}

uint64_t TCGLLVMTranslator::toInteger(llvm::Value *v) const {
    if (ConstantInt *cste = dyn_cast<ConstantInt>(v)) {
        return *cste->getValue().getRawData();
    }

    llvm::errs() << *v << '\n';
    assert(false && "Not a constant");
    abort();
}

#ifdef CONFIG_SYMBEX

void TCGLLVMTranslator::initializeNativeCpuState() {
    m_cpuType = m_module->getTypeByName("struct.CPUX86State");
    assert(m_cpuType && "Could not find CPUX86State in LLVM bitcode");
}

void TCGLLVMTranslator::initializeHelpers() {
    m_helperForkAndConcretize = nullptr;
#if !defined(STATIC_TRANSLATOR)
    m_helperForkAndConcretize = m_module->getFunction("tcg_llvm_fork_and_concretize");
    if (!m_helperForkAndConcretize) {
        abort();
    }
#endif

    m_qemu_ld_helpers[0] = m_module->getFunction("helper_ldb_mmu");
    m_qemu_ld_helpers[1] = m_module->getFunction("helper_ldw_mmu");
    m_qemu_ld_helpers[2] = m_module->getFunction("helper_ldl_mmu");
    m_qemu_ld_helpers[3] = m_module->getFunction("helper_ldq_mmu");
    m_qemu_ld_helpers[4] = m_module->getFunction("helper_ldq_mmu");

    m_qemu_st_helpers[0] = m_module->getFunction("helper_stb_mmu");
    m_qemu_st_helpers[1] = m_module->getFunction("helper_stw_mmu");
    m_qemu_st_helpers[2] = m_module->getFunction("helper_stl_mmu");
    m_qemu_st_helpers[3] = m_module->getFunction("helper_stq_mmu");
    m_qemu_st_helpers[4] = m_module->getFunction("helper_stq_mmu");

    for (int i = 0; i < 5; ++i) {
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
void TCGLLVMTranslator::attachPcMetadata(Instruction *instr, uint64_t pc) {
    LLVMContext &C = instr->getContext();
    SmallVector<Metadata *, 1> args;
    args.push_back(ValueAsMetadata::get(ConstantInt::get(wordType(64), pc)));
    MDNode *N = MDNode::get(C, ArrayRef<Metadata *>(args));
    instr->setMetadata("s2e.pc", N);
}

Value *TCGLLVMTranslator::attachCurrentPc(Value *v) {
    Instruction *instr = dyn_cast<Instruction>(v);
    if (instr) {
        attachPcMetadata(instr, m_currentPc);
    }
    return v;
}
#else
Value *TCGLLVMTranslator::attachCurrentPc(Value *v) {
    return v;
}
#endif

Value *TCGLLVMTranslator::getPtrForValue(int idx) {
    TCGContext *s = m_tcgContext;
    TCGTemp &temp = s->temps[idx];

    assert(idx < s->nb_globals || s->temps[idx].temp_local);

    if (m_memValuesPtr[idx] == NULL) {
        assert(idx < s->nb_globals);

        if (temp.fixed_reg) {
            assert(idx == 0); // Assume we access CPUState
            Value *v = &*m_tbFunction->arg_begin();

            m_memValuesPtr[idx] = m_builder.CreatePointerCast(v, tcgPtrType(temp.type), StringRef(temp.name) + "_ptr");
        } else {
            m_memValuesPtr[idx] = generateCpuStatePtr(temp.mem_offset, tcgType(temp.type)->getScalarSizeInBits() / 8);
        }
    }

    return m_memValuesPtr[idx];
}

void TCGLLVMTranslator::delValue(int idx) {
    assert(idx >= 0 && idx < TCG_MAX_TEMPS);
    m_values[idx] = NULL;
}

void TCGLLVMTranslator::delPtrForValue(int idx) {
    assert(idx >= 0 && idx < TCG_MAX_TEMPS);
    m_memValuesPtr[idx] = NULL;
}

unsigned TCGLLVMTranslator::getValueBits(int idx) {
    assert(idx >= 0 && idx < TCG_MAX_TEMPS);

    switch (m_tcgContext->temps[idx].type) {
        case TCG_TYPE_I32:
            return 32;
        case TCG_TYPE_I64:
            return 64;
        default:
            assert(false && "Unknown size");
    }
    return 0;
}

Value *TCGLLVMTranslator::getValue(TCGArg arg) {
    int idx = temp_idx(arg_temp(arg));
    assert(idx >= 0 && idx < TCG_MAX_TEMPS);

    const TCGTemp &temp = m_tcgContext->temps[idx];

    if (m_values[idx] == NULL) {
        if (temp.temp_global) {
            assert(idx < m_tcgContext->nb_globals);
            if (temp.fixed_reg) {
                assert(idx == 0);
                Value *v = &*m_tbFunction->arg_begin();
                m_values[idx] = m_builder.CreatePtrToInt(v, tcgType(temp.type), StringRef(temp.name) + "_v");
            } else {
                m_values[idx] = m_builder.CreateLoad(getPtrForValue(idx), StringRef(temp.name) + "_v");
            }
        } else if (temp.temp_local) {
            m_values[idx] = m_builder.CreateLoad(getPtrForValue(idx));
            std::ostringstream name;
            name << "loc" << (idx - m_tcgContext->nb_globals) << "_v";
            m_values[idx]->setName(name.str());
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

void TCGLLVMTranslator::setValue(TCGArg arg, Value *v) {
    int idx = temp_idx(arg_temp(arg));
    assert(idx >= 0 && idx < TCG_MAX_TEMPS);

    delValue(idx);
    m_values[idx] = v;

    const TCGTemp *tmp = &m_tcgContext->temps[idx];

    if (!v->hasName() && !isa<Constant>(v)) {
        if (tmp->temp_global) {
            v->setName(StringRef(tmp->name) + "_v");
        } else if (tmp->temp_local) {
            std::ostringstream name;
            name << "loc" << (idx - m_tcgContext->nb_globals) << "_v";
            v->setName(name.str());
        } else {
            std::ostringstream name;
            name << "tmp" << (idx - m_tcgContext->nb_globals) << "_v";
            v->setName(name.str());
        }
    }

    if (tmp->temp_global) {
        assert(idx < m_tcgContext->nb_globals);
        // We need to save a global copy of a value
        m_builder.CreateStore(v, getPtrForValue(idx));

        if (tmp->fixed_reg) {
            /* Invalidate all dependent global vals and pointers */
            assert(false);
            for (int i = 0; i < m_tcgContext->nb_globals; ++i) {
                if (i != idx && !tmp->fixed_reg && m_globalsIdx[i] == idx) {
                    delValue(i);
                    delPtrForValue(i);
                }
            }
        }
    } else if (tmp->temp_local) {
        // We need to save an in-memory copy of a value
        m_builder.CreateStore(v, getPtrForValue(idx));
    } else {
        // We don't need to save the temp value anywhere, it will be
        // dead at the end of the basic block. We just keep it in m_values
        // in case some other instruction references it.
    }
}

void TCGLLVMTranslator::initGlobalsAndLocalTemps() {
    TCGContext *s = m_tcgContext;

    int reg_to_idx[TCG_TARGET_NB_REGS];

    for (int i = 0; i < TCG_TARGET_NB_REGS; ++i) {
        reg_to_idx[i] = -1;
    }

    int argNumber = 0;
    for (int i = 0; i < s->nb_globals; ++i) {
        if (s->temps[i].fixed_reg) {
            // This global is in fixed host register. We are
            // mapping such registers to function arguments
            m_globalsIdx[i] = argNumber++;
            reg_to_idx[s->temps[i].reg] = i;

        } else {
            // This global is in memory at (mem_reg + mem_offset).
            // Base value is not known yet, so just store mem_reg
            m_globalsIdx[i] = s->temps[i].mem_base->reg;
        }
    }

    // Map mem_reg to index for memory-based globals
    for (int i = 0; i < s->nb_globals; ++i) {
        if (!s->temps[i].fixed_reg) {
            assert(reg_to_idx[m_globalsIdx[i]] >= 0);
            m_globalsIdx[i] = reg_to_idx[m_globalsIdx[i]];
        }
    }

    // Allocate local temps
    for (int i = s->nb_globals; i < TCG_MAX_TEMPS; ++i) {
        if (s->temps[i].temp_local) {
            std::ostringstream pName;
            pName << "loc_" << (i - s->nb_globals) << "ptr";
            m_memValuesPtr[i] = m_builder.CreateAlloca(tcgType(s->temps[i].type), 0, pName.str());
        }
    }
}

void TCGLLVMTranslator::loadNativeCpuState(Function *f) {
    m_cpuState = &*(f->arg_begin());
    m_cpuStateInt = dyn_cast<Instruction>(m_builder.CreatePtrToInt(m_cpuState, wordType()));

    auto ci = ConstantInt::get(wordType(), 0);
    auto add = BinaryOperator::Create(Instruction::Add, ci, ci, "");
    m_noop = m_builder.Insert(add);

    m_eip = generateCpuStatePtr(m_tcgContext->env_offset_eip, m_tcgContext->env_sizeof_eip);
    m_ccop = generateCpuStatePtr(m_tcgContext->env_offset_ccop, m_tcgContext->env_sizeof_ccop);

    if (m_eip_last_gep_index == 0) {
        SmallVector<Value *, 3> gepElements;
        bool ok = getCpuFieldGepIndexes(m_tcgContext->env_offset_eip, sizeof(target_ulong), gepElements);
        if (!ok) {
            abort();
        }

        m_eip_last_gep_index = (unsigned) dyn_cast<ConstantInt>(gepElements.back())->getZExtValue();
    }
}

BasicBlock *TCGLLVMTranslator::getLabel(TCGArg i) {
    TCGLabel *label = arg_label(i);

    auto it = m_labels.find(label);
    if (it != m_labels.end()) {
        return it->second;
    }

    std::ostringstream bbName;
    bbName << "label_" << label->id;
    auto bb = BasicBlock::Create(getContext(), bbName.str());
    m_labels[label] = bb;
    return bb;
}

void TCGLLVMTranslator::startNewBasicBlock(BasicBlock *bb) {
    if (!bb) {
        bb = BasicBlock::Create(getContext());
    } else {
        assert(bb->getParent() == 0);
    }

    if (!m_builder.GetInsertBlock()->getTerminator()) {
        m_builder.CreateBr(bb);
    }

    m_tbFunction->getBasicBlockList().push_back(bb);
    m_builder.SetInsertPoint(bb);

    /* Invalidate all temps */
    for (int i = 0; i < TCG_MAX_TEMPS; ++i) {
        delValue(i);
    }

    /* Invalidate all pointers to globals */
    for (int i = 0; i < m_tcgContext->nb_globals; ++i) {
        delPtrForValue(i);
    }
}

Value *TCGLLVMTranslator::generateCpuStatePtr(uint64_t registerOffset, unsigned sizeInBytes) {
    SmallVector<Value *, 3> gepElements;
    Instruction *ret = nullptr;
    auto regsz = std::make_pair(registerOffset, sizeInBytes);

    // XXX: assumes x86
    static unsigned TARGET_LONG_BYTES = TARGET_LONG_BITS / 8;

    if ((registerOffset % (TARGET_LONG_BITS / 8)) == 0) {
        auto &instList = m_tbFunction->begin()->getInstList();
        auto it = m_registers.find(regsz);

        if (it != m_registers.end()) {
            return (*it).second;
        } else {
            bool ok = getCpuFieldGepIndexes(registerOffset, sizeInBytes, gepElements);
            if (ok) {
                ret = GetElementPtrInst::Create(nullptr, m_cpuState,
                                                ArrayRef<Value *>(gepElements.begin(), gepElements.end()));
                instList.push_front(ret);
                m_registers[regsz] = ret;
            }
        }
    }

    if (ret && sizeInBytes < TARGET_LONG_BYTES) {
        auto ty = intPtrType(sizeInBytes * 8);
        ret = CastInst::CreatePointerCast(ret, ty, "", ret->getNextNode());
        m_registers[regsz] = ret;
        return ret;
    }

    if (!ret) {
        // If gep fails, fallback to pointer arithmetic
        auto ci = ConstantInt::get(wordType(), registerOffset);
        auto add = BinaryOperator::Create(Instruction::Add, m_cpuStateInt, ci, "", m_noop);
        ret = CastInst::CreateBitOrPointerCast(add, intPtrType(sizeInBytes * 8), "", m_noop);
        m_registers[regsz] = ret;
    }

    return ret;
}

void TCGLLVMTranslator::generateQemuCpuLoad(const TCGArg *args, unsigned memBits, unsigned regBits, bool signExtend) {
    assert(getValue(args[1])->getType() == wordType());
    assert(memBits <= regBits);
    Value *gep = generateCpuStatePtr(args[2], memBits / 8);
    Value *v;

    v = m_builder.CreateLoad(gep);
    v = m_builder.CreateTrunc(v, intType(memBits));

    if (signExtend) {
        setValue(args[0], m_builder.CreateSExt(v, intType(regBits)));
    } else {
        setValue(args[0], m_builder.CreateZExt(v, intType(regBits)));
    }
}

void TCGLLVMTranslator::generateQemuCpuStore(const TCGArg *args, unsigned memBits, Value *valueToStore) {
    // TODO: args[1] contains a ptr to cpu state, we don't use it.
    tcg_target_ulong offset = args[2];

    if (memBits == TARGET_LONG_BITS && offset == m_tcgContext->env_offset_eip) {
        valueToStore = handleSymbolicPcAssignment(valueToStore);
    }

    Value *gep = generateCpuStatePtr(offset, memBits / 8);
    Value *v = NULL;

    v = m_builder.CreatePointerCast(gep, intType(memBits)->getPointerTo());

#ifdef STATIC_TRANSLATOR
    StoreInst *s = m_builder.CreateStore(m_builder.CreateTrunc(valueToStore, intType(memBits)), v);
    if (isPcAssignment(gep)) {
        m_info.pcAssignments.push_back(s);
    }
#else
    m_builder.CreateStore(m_builder.CreateTrunc(valueToStore, intType(memBits)), v);
#endif
}

Value *TCGLLVMTranslator::generateQemuMemOp(bool ld, Value *value, Value *addr, int mem_index, int bits) {
    assert(addr->getType() == intType(TARGET_LONG_BITS));
    assert(ld || value->getType() == intType(bits));
    assert(TCG_TARGET_REG_BITS == 64); // XXX
    TCGMemOp memop = get_memop(mem_index);
    unsigned helper_size = memop & MO_SIZE;

#ifdef CONFIG_SOFTMMU
#if defined(CONFIG_SYMBEX)
    auto retAddr = Constant::getNullValue(intPtrType(8));

    if (ld) {
        Value *v = attachCurrentPc(
            m_builder.CreateCall(m_qemu_ld_helpers[helper_size],
                                 {m_cpuState, addr, ConstantInt::get(intType(8 * sizeof(int)), mem_index), retAddr}));

        if (memop & MO_SIGN) {
            v = m_builder.CreateSExt(v, intType(bits));
        } else {
            v = m_builder.CreateZExt(v, intType(bits));
        }

        return v;
    } else {
        auto new_bits = (1 << helper_size) * 8;
        if (new_bits < bits) {
            value = m_builder.CreateTrunc(value, intType(new_bits));
        }

        attachCurrentPc(m_builder.CreateCall(
            m_qemu_st_helpers[helper_size],
            {m_cpuState, addr, value, ConstantInt::get(intType(8 * sizeof(int)), mem_index), retAddr}));
        return NULL;
    }
#endif
#else  // CONFIG_SOFTMMU
    abort();
    addr = m_builder.CreateZExt(addr, wordType());
    addr = m_builder.CreateAdd(addr, ConstantInt::get(wordType(), GUEST_BASE));
    addr = m_builder.CreateIntToPtr(addr, intPtrType(bits));
    if (ld) {
        return m_builder.CreateLoad(addr);
    } else {
        m_builder.CreateStore(value, addr);
        return NULL;
    }
#endif // CONFIG_SOFTMMU
}

int TCGLLVMTranslator::generateOperation(const TCGOp *op) {
    Value *v = NULL;
    const TCGOpDef &def = tcg_op_defs[op->opc];
    int nb_args = def.nb_args;

    switch (op->opc) {
        case INDEX_op_insn_start:
            break;

        case INDEX_op_discard:
            delValue(temp_idx(arg_temp(op->args[0])));
            break;

        case INDEX_op_call: {
            int nb_oargs = TCGOP_CALLO(op);
            int nb_iargs = TCGOP_CALLI(op);
            int nb_cargs = def.nb_cargs;

            nb_args = nb_oargs + nb_iargs + nb_cargs + 1;

            std::vector<Value *> argValues;
            std::vector<Type *> argTypes;

            for (int i = 0; i < nb_iargs; ++i) {
                TCGArg arg = op->args[nb_oargs + i];
                if (arg != TCG_CALL_DUMMY_ARG) {
                    Value *v = getValue(arg);
                    argValues.push_back(v);
                    argTypes.push_back(v->getType());
                }
            }

            assert(nb_oargs == 0 || nb_oargs == 1);

            Type *retType;
            if (nb_oargs == 0) {
                retType = Type::getVoidTy(getContext());
            } else {
                int retIdx = temp_idx(arg_temp(op->args[0]));
                retType = wordType(getValueBits(retIdx));
            }

            tcg_target_ulong helperAddress = op->args[nb_oargs + nb_iargs];
            assert(helperAddress);

            const char *helperName = tcg_helper_get_name(m_tcgContext, (void *) helperAddress);
            assert(helperName);

            std::string funcName = std::string("helper_") + helperName;
            Function *helperFunc = m_module->getFunction(funcName);

#ifndef STATIC_TRANSLATOR
            if (!helperFunc) {
                helperFunc = Function::Create(FunctionType::get(retType, argTypes, false), Function::ExternalLinkage,
                                              funcName, m_module.get());
                /* XXX: Why do we need this ? */
                sys::DynamicLibrary::AddSymbol(funcName, (void *) helperAddress);
            }
#endif

            FunctionType *FTy = cast<FunctionType>(cast<PointerType>(helperFunc->getType())->getElementType());

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
                }
            }

            Value *result = m_builder.CreateCall(helperFunc, ArrayRef<Value *>(argValues));

            for (int i = 0; i < m_tcgContext->nb_globals; ++i) {
                // Invalidate in-memory values because
                // function might have changed them
                delValue(i);

                // Invalidate all pointers to globals
                delPtrForValue(i);
            }

            for (int i = m_tcgContext->nb_globals; i < TCG_MAX_TEMPS; ++i) {
                if (m_tcgContext->temps[i].temp_local) {
                    delValue(i);
                }
            }

            if (nb_oargs == 1) {
                setValue(op->args[0], result);
            }
        } break;

        case INDEX_op_br:
            m_builder.CreateBr(getLabel(op->args[0]));
            startNewBasicBlock();
            break;

#define __OP_BRCOND_C(tcg_cond, cond)                                                 \
    case tcg_cond:                                                                    \
        v = m_builder.CreateICmp##cond(getValue(op->args[0]), getValue(op->args[1])); \
        break;

#define __OP_BRCOND(opc_name, bits)                                \
    case opc_name: {                                               \
        assert(getValue(op->args[0])->getType() == intType(bits)); \
        assert(getValue(op->args[1])->getType() == intType(bits)); \
        switch (op->args[2]) {                                     \
            __OP_BRCOND_C(TCG_COND_EQ, EQ)                         \
            __OP_BRCOND_C(TCG_COND_NE, NE)                         \
            __OP_BRCOND_C(TCG_COND_LT, SLT)                        \
            __OP_BRCOND_C(TCG_COND_GE, SGE)                        \
            __OP_BRCOND_C(TCG_COND_LE, SLE)                        \
            __OP_BRCOND_C(TCG_COND_GT, SGT)                        \
            __OP_BRCOND_C(TCG_COND_LTU, ULT)                       \
            __OP_BRCOND_C(TCG_COND_GEU, UGE)                       \
            __OP_BRCOND_C(TCG_COND_LEU, ULE)                       \
            __OP_BRCOND_C(TCG_COND_GTU, UGT)                       \
            default:                                               \
                tcg_abort();                                       \
        }                                                          \
        BasicBlock *bb = BasicBlock::Create(getContext());         \
        m_builder.CreateCondBr(v, getLabel(op->args[3]), bb);      \
        startNewBasicBlock(bb);                                    \
    } break;

            __OP_BRCOND(INDEX_op_brcond_i32, 32)

#if TCG_TARGET_REG_BITS == 64
            __OP_BRCOND(INDEX_op_brcond_i64, 64)
#endif

#undef __OP_BRCOND_C
#undef __OP_BRCOND

        case INDEX_op_set_label: {
            assert(getLabel(op->args[0])->getParent() == 0);
            startNewBasicBlock(getLabel(op->args[0]));
        } break;

        case INDEX_op_movi_i32:
            setValue(op->args[0], ConstantInt::get(intType(32), op->args[1]));
            break;

        case INDEX_op_mov_i32:
            // Move operation may perform truncation of the value
            assert(getValue(op->args[1])->getType() == intType(32) || getValue(op->args[1])->getType() == intType(64));
            setValue(op->args[0], m_builder.CreateTrunc(getValue(op->args[1]), intType(32)));
            break;

#if TCG_TARGET_REG_BITS == 64
        case INDEX_op_movi_i64:
            setValue(op->args[0], ConstantInt::get(intType(64), op->args[1]));
            break;

        case INDEX_op_mov_i64:
            assert(getValue(op->args[1])->getType() == intType(64));
            setValue(op->args[0], getValue(op->args[1]));
            break;
#endif

/* size extensions */
#define __EXT_OP(opc_name, truncBits, opBits, signE)                                                                   \
    case opc_name:                                                                                                     \
        /*                                                                                                             \
        assert(getValue(op->args[1])->getType() == intType(opBits) ||                                                  \
               getValue(op->args[1])->getType() == intType(truncBits));                                                \
        */                                                                                                             \
        setValue(op->args[0], m_builder.Create##signE##Ext(                                                            \
                                  m_builder.CreateTrunc(getValue(op->args[1]), intType(truncBits)), intType(opBits))); \
        break;

            __EXT_OP(INDEX_op_ext8s_i32, 8, 32, S)
            __EXT_OP(INDEX_op_ext8u_i32, 8, 32, Z)
            __EXT_OP(INDEX_op_ext16s_i32, 16, 32, S)
            __EXT_OP(INDEX_op_ext16u_i32, 16, 32, Z)

#if TCG_TARGET_REG_BITS == 64
            __EXT_OP(INDEX_op_ext8s_i64, 8, 64, S)
            __EXT_OP(INDEX_op_ext8u_i64, 8, 64, Z)
            __EXT_OP(INDEX_op_ext16s_i64, 16, 64, S)
            __EXT_OP(INDEX_op_ext16u_i64, 16, 64, Z)

            __EXT_OP(INDEX_op_ext_i32_i64, 32, 64, S)
            __EXT_OP(INDEX_op_ext32s_i64, 32, 64, S)

            __EXT_OP(INDEX_op_extu_i32_i64, 32, 64, Z)
            __EXT_OP(INDEX_op_ext32u_i64, 32, 64, Z)
            __EXT_OP(INDEX_op_extrl_i64_i32, 32, 64, Z)
#endif

#undef __EXT_OP

#define __LD_OP(opc_name, memBits, regBits, signE)                     \
    case opc_name:                                                     \
        generateQemuCpuLoad(op->args, memBits, regBits, signE == 'S'); \
        break;

#define __ST_OP(opc_name, memBits, regBits)                           \
    case opc_name: {                                                  \
        assert(getValue(op->args[0])->getType() == intType(regBits)); \
        assert(getValue(op->args[1])->getType() == wordType());       \
        Value *valueToStore = getValue(op->args[0]);                  \
                                                                      \
        generateQemuCpuStore(op->args, memBits, valueToStore);        \
    } break;

            __LD_OP(INDEX_op_ld8u_i32, 8, 32, 'Z')
            __LD_OP(INDEX_op_ld8s_i32, 8, 32, 'S')
            __LD_OP(INDEX_op_ld16u_i32, 16, 32, 'Z')
            __LD_OP(INDEX_op_ld16s_i32, 16, 32, 'S')
            __LD_OP(INDEX_op_ld_i32, 32, 32, 'Z')

            __ST_OP(INDEX_op_st8_i32, 8, 32)
            __ST_OP(INDEX_op_st16_i32, 16, 32)
            __ST_OP(INDEX_op_st_i32, 32, 32)

#if TCG_TARGET_REG_BITS == 64
            __LD_OP(INDEX_op_ld8u_i64, 8, 64, 'Z')
            __LD_OP(INDEX_op_ld8s_i64, 8, 64, 'S')
            __LD_OP(INDEX_op_ld16u_i64, 16, 64, 'Z')
            __LD_OP(INDEX_op_ld16s_i64, 16, 64, 'S')
            __LD_OP(INDEX_op_ld32u_i64, 32, 64, 'Z')
            __LD_OP(INDEX_op_ld32s_i64, 32, 64, 'S')
            __LD_OP(INDEX_op_ld_i64, 64, 64, 'Z')

            __ST_OP(INDEX_op_st8_i64, 8, 64)
            __ST_OP(INDEX_op_st16_i64, 16, 64)
            __ST_OP(INDEX_op_st32_i64, 32, 64)
            __ST_OP(INDEX_op_st_i64, 64, 64)
#endif

#undef __LD_OP
#undef __ST_OP

/* arith */
#define __ARITH_OP(opc_name, op1, bits)                       \
    case opc_name: {                                          \
        Value *v1 = getValue(op->args[1]);                    \
        Value *v2 = getValue(op->args[2]);                    \
        adjustTypeSize(bits, &v1, &v2);                       \
        assert(v1->getType() == intType(bits));               \
        assert(v2->getType() == intType(bits));               \
        setValue(op->args[0], m_builder.Create##op1(v1, v2)); \
    } break;

#define __ARITH_OP_DIV2(opc_name, signE, bits)                                                                   \
    case opc_name:                                                                                               \
        assert(getValue(op->args[2])->getType() == intType(bits));                                               \
        assert(getValue(op->args[3])->getType() == intType(bits));                                               \
        assert(getValue(op->args[4])->getType() == intType(bits));                                               \
        v = m_builder.CreateShl(m_builder.CreateZExt(getValue(op->args[3]), intType(bits * 2)),                  \
                                m_builder.CreateZExt(ConstantInt::get(intType(bits), bits), intType(bits * 2))); \
        v = m_builder.CreateOr(v, m_builder.CreateZExt(getValue(op->args[2]), intType(bits * 2)));               \
        setValue(op->args[0], m_builder.Create##signE##Div(v, getValue(op->args[4])));                           \
        setValue(op->args[1], m_builder.Create##signE##Rem(v, getValue(op->args[4])));                           \
        break;

#define __ARITH_OP_ROT(opc_name, op1, op2, bits)                                                                      \
    case opc_name:                                                                                                    \
        assert(getValue(op->args[1])->getType() == intType(bits));                                                    \
        assert(getValue(op->args[2])->getType() == intType(bits));                                                    \
        v = m_builder.CreateSub(ConstantInt::get(intType(bits), bits), getValue(op->args[2]));                        \
        setValue(op->args[0], m_builder.CreateOr(m_builder.Create##op1(getValue(op->args[1]), getValue(op->args[2])), \
                                                 m_builder.Create##op2(getValue(op->args[1]), v)));                   \
        break;

#define __ARITH_OP_I(opc_name, op1, i, bits)                                                                     \
    case opc_name:                                                                                               \
        assert(getValue(op->args[1])->getType() == intType(bits));                                               \
        setValue(op->args[0], m_builder.Create##op1(ConstantInt::get(intType(bits), i), getValue(op->args[1]))); \
        break;

#define __ARITH_OP_BSWAP(opc_name, sBits, bits)                                                                  \
    case opc_name: {                                                                                             \
        assert(getValue(op->args[1])->getType() == intType(bits));                                               \
        Type *Tys[] = {intType(sBits)};                                                                          \
        Function *bswap = Intrinsic::getDeclaration(m_module.get(), Intrinsic::bswap, ArrayRef<Type *>(Tys, 1)); \
        v = m_builder.CreateTrunc(getValue(op->args[1]), intType(sBits));                                        \
        setValue(op->args[0], m_builder.CreateZExt(m_builder.CreateCall(bswap, v), intType(bits)));              \
    } break;

            __ARITH_OP(INDEX_op_add_i32, Add, 32)
            __ARITH_OP(INDEX_op_sub_i32, Sub, 32)
            __ARITH_OP(INDEX_op_mul_i32, Mul, 32)

#ifdef TCG_TARGET_HAS_div_i32
            __ARITH_OP(INDEX_op_div_i32, SDiv, 32)
            __ARITH_OP(INDEX_op_divu_i32, UDiv, 32)
            __ARITH_OP(INDEX_op_rem_i32, SRem, 32)
            __ARITH_OP(INDEX_op_remu_i32, URem, 32)
#else
            __ARITH_OP_DIV2(INDEX_op_div2_i32, S, 32)
            __ARITH_OP_DIV2(INDEX_op_divu2_i32, U, 32)
#endif

            __ARITH_OP(INDEX_op_and_i32, And, 32)
            __ARITH_OP(INDEX_op_or_i32, Or, 32)
            __ARITH_OP(INDEX_op_xor_i32, Xor, 32)

            __ARITH_OP(INDEX_op_shl_i32, Shl, 32)
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
            __ARITH_OP(INDEX_op_div_i64, SDiv, 64)
            __ARITH_OP(INDEX_op_divu_i64, UDiv, 64)
            __ARITH_OP(INDEX_op_rem_i64, SRem, 64)
            __ARITH_OP(INDEX_op_remu_i64, URem, 64)
#else
            __ARITH_OP_DIV2(INDEX_op_div2_i64, S, 64)
            __ARITH_OP_DIV2(INDEX_op_divu2_i64, U, 64)
#endif

            __ARITH_OP(INDEX_op_and_i64, And, 64)
            __ARITH_OP(INDEX_op_or_i64, Or, 64)
            __ARITH_OP(INDEX_op_xor_i64, Xor, 64)

            __ARITH_OP(INDEX_op_shl_i64, Shl, 64)
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
#define __OP_QEMU_ST(opc_name, bits)                                                                   \
    case opc_name:                                                                                     \
        generateQemuMemOp(false, m_builder.CreateIntCast(getValue(op->args[0]), intType(bits), false), \
                          getValue(op->args[1]), op->args[2], bits);                                   \
        break;

#define __OP_QEMU_LD(opc_name, bits)                                                 \
    case opc_name:                                                                   \
        v = generateQemuMemOp(true, NULL, getValue(op->args[1]), op->args[2], bits); \
        setValue(op->args[0], v);                                                    \
        break;

            __OP_QEMU_ST(INDEX_op_qemu_st_i32, 32)
            __OP_QEMU_ST(INDEX_op_qemu_st_i64, 64)

            __OP_QEMU_LD(INDEX_op_qemu_ld_i32, 32)
            __OP_QEMU_LD(INDEX_op_qemu_ld_i64, 64)

#undef __OP_QEMU_LD
#undef __OP_QEMU_ST

        case INDEX_op_exit_tb: {
#ifdef STATIC_TRANSLATOR
            ReturnInst *ret = m_builder.CreateRet(ConstantInt::get(wordType(), op->args[0]));
            m_info.returnInstructions.push_back(ret);
#else
            m_builder.CreateRet(ConstantInt::get(wordType(), op->args[0]));
#endif
        } break;

        case INDEX_op_goto_tb:
            // tb linking is disabled
            break;

        case INDEX_op_deposit_i32: {
            Value *arg1 = getValue(op->args[1]);
            Value *arg2 = getValue(op->args[2]);
            arg2 = m_builder.CreateTrunc(arg2, intType(32));

            uint32_t ofs = op->args[3];
            uint32_t len = op->args[4];

            if (ofs == 0 && len == 32) {
                setValue(op->args[0], arg2);
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
            setValue(op->args[0], ret);
        } break;
#if TCG_TARGET_REG_BITS == 64
        case INDEX_op_deposit_i64: {
            Value *arg1 = getValue(op->args[1]);
            Value *arg2 = getValue(op->args[2]);
            arg2 = m_builder.CreateTrunc(arg2, intType(64));

            uint32_t ofs = op->args[3];
            uint32_t len = op->args[4];

            if (0 == ofs && 64 == len) {
                setValue(op->args[0], arg2);
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
            setValue(op->args[0], ret);
        } break;
#endif

        default:
            std::cerr << "ERROR: unknown TCG micro operation '" << def.name << "'" << std::endl;
            tcg_abort();
            break;
    }

    return nb_args;
}

bool TCGLLVMTranslator::isInstrumented(llvm::Function *tb) {
    std::string name = tb->getName();
    return name.find("insttb") != std::string::npos;
}

std::string TCGLLVMTranslator::generateName() {
    std::ostringstream fName;

    fName << "tcg-llvm-" << m_tbCount++ << "-" << std::hex << m_tb->pc;

    return fName.str();
}

Function *TCGLLVMTranslator::createTbFunction(const std::string &name) {
    FunctionType *tbFunctionType = tbType();

    return Function::Create(tbFunctionType, Function::ExternalLinkage, name, m_module.get());
}

///
/// \brief This function removes the branch that causes an early exit from
/// a translation block if there is an interrupt pending.
///
/// LLVM translation blocks are not chained, so there is no need for exit.
///
/// The following is the pattern generated by the translator frontend.
/// This function replaces the conditional branch by a direct branch to the main
/// part of the translation block.
///
/// define i64 @tcg-llvm-tb-c18f4300-1d-42a-0-4002b4(%struct.CPUX86State*) #21 {
/// entry:
///   %1 = getelementptr %struct.CPUX86State, %struct.CPUX86State* %0, i32 0, i32 18
///   %2 = getelementptr %struct.CPUX86State, %struct.CPUX86State* %0, i32 0, i32 1
///   ...
///   %5 = icmp ne i32 %tmp12_v, 0
///   br i1 %5, label %label_0, label %6
///
/// ; <label>:6:                                      ; preds = %entry
///   %env_v1 = ptrtoint %struct.CPUX86State* %0 to i64
///   %7 = add i64 %env_v1, 872
///   %8 = inttoptr i64 %7 to i64*
///   ...
/// label_0:                                          ; preds = %entry
/// ret i64 23455151949251
/// }
///
///
void TCGLLVMTranslator::removeInterruptExit() {
    auto &bb = m_tbFunction->front();
    auto br = dyn_cast<BranchInst>(bb.getTerminator());
    auto target = br->getSuccessor(1);
    br->eraseFromParent();
    auto newBr = BranchInst::Create(target);
    bb.getInstList().push_back(newBr);
}

Function *TCGLLVMTranslator::generateCode(TCGContext *s, TranslationBlock *tb) {
#ifdef STATIC_TRANSLATOR
    m_info.clear();
#endif

    m_tcgContext = s;
    m_tb = tb;

    std::string name = generateName();

    m_registers.clear();

    Function *existingTb = m_module->getFunction(name);
    if (existingTb) {
        return existingTb;
    }

    m_tbFunction = createTbFunction(name);
    m_tbFunction->addFnAttr(Attribute::AlwaysInline);

    BasicBlock *basicBlock = BasicBlock::Create(getContext(), "entry", m_tbFunction);
    m_builder.SetInsertPoint(basicBlock);

    /* Prepare globals and temps information */
    initGlobalsAndLocalTemps();

    loadNativeCpuState(m_tbFunction);

    /* Generate code for each opc */
    const TCGOp *op;
    QTAILQ_FOREACH (op, &s->ops, link) {
        int opc = op->opc;

        switch (opc) {
#if defined(STATIC_TRANSLATOR)
            case INDEX_op_insn_start: {
                m_currentPc = op->args[0] - tb->cs_base;
            } break;
#elif defined(CONFIG_SYMBEX)
            case INDEX_op_insn_start: {
                assert(TARGET_INSN_START_WORDS == 2);
                uint64_t curpc = op->args[0] - tb->cs_base;
                uint64_t cc_op = op->args[1];

                Value *valueToStore = handleSymbolicPcAssignment(ConstantInt::get(wordType(), curpc));

                TCGArg args[3];
                args[0] = 0; // Unused
                args[1] = temp_arg(&m_tcgContext->temps[0]);
                args[2] = m_tcgContext->env_offset_eip;
                generateQemuCpuStore(args, m_tcgContext->env_sizeof_eip * 8, valueToStore);

                if (cc_op != CC_OP_DYNAMIC) {
                    args[0] = 0; // Unused
                    args[1] = temp_arg(&m_tcgContext->temps[0]);
                    args[2] = m_tcgContext->env_offset_ccop;
                    valueToStore = ConstantInt::get(wordType(m_tcgContext->env_sizeof_ccop * 8), cc_op);
                    generateQemuCpuStore(args, m_tcgContext->env_sizeof_ccop * 8, valueToStore);
                }
            } break;
#endif

            default:
                generateOperation(op);
        }
    }

    /* Finalize function */
    if (!isa<ReturnInst>(m_tbFunction->back().back())) {
#ifdef STATIC_TRANSLATOR
        ReturnInst *ret = m_builder.CreateRet(ConstantInt::get(wordType(), 0));
        m_info.returnInstructions.push_back(ret);
#else
        m_builder.CreateRet(ConstantInt::get(wordType(), 0));
#endif
    }

    /* Clean up unused m_values */
    for (int i = 0; i < TCG_MAX_TEMPS; ++i) {
        delValue(i);
    }

    /* Delete pointers after deleting values */
    for (int i = 0; i < TCG_MAX_TEMPS; ++i) {
        delPtrForValue(i);
    }

    m_labels.clear();

    if (tb->cflags & CF_HAS_INTERRUPT_EXIT) {
        removeInterruptExit();
    }

    std::string errstr;
    llvm::raw_string_ostream erros(errstr);
    if (verifyFunction(*m_tbFunction, &erros)) {
        std::error_code error;
        std::stringstream ss;
        ss << "llvm-" << getpid() << ".log";
        llvm::raw_fd_ostream os(ss.str(), error, llvm::sys::fs::F_None);
        os << "Dumping function:\n";
        os.flush();
        os << *m_tbFunction << "\n";
        os << errstr << "\n";
        os.close();
        abort();
    }

#ifdef STATIC_TRANSLATOR
    computeStaticBranchTargets();
#endif

// KLEE will optimize the function later
// m_functionPassManager->run(*m_tbFunction);

// XXX: implement proper logging
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
void TCGLLVMTranslator::computeStaticBranchTargets() {
    unsigned sz = m_info.returnInstructions.size();

    // Simple case, only one assignment
    if (sz == 1) {
        StoreInst *si = m_info.pcAssignments.back();
        ConstantInt *ci = dyn_cast<ConstantInt>(si->getValueOperand());
        if (ci) {
            m_info.staticBranchTargets.push_back(ci->getZExtValue());
        }
    } else if (sz == 2) {
        unsigned asz = m_info.pcAssignments.size();

        // Figure out which is the true branch, which is the false one.
        // Pick the last 2 pc assignments
        StoreInst *s1 = m_info.pcAssignments[asz - 2];
        ConstantInt *c1 = dyn_cast<ConstantInt>(s1->getValueOperand());

        StoreInst *s2 = m_info.pcAssignments[asz - 1];
        ConstantInt *c2 = dyn_cast<ConstantInt>(s2->getValueOperand());

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
            llvm::BranchInst *Bi = dyn_cast<llvm::BranchInst>(p1->getTerminator());
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

bool TCGLLVMTranslator::getCpuFieldGepIndexes(unsigned offset, unsigned sizeInBytes,
                                              SmallVector<Value *, 3> &gepIndexes) {

    Type *curType = m_cpuType;
    auto &dataLayout = m_module->getDataLayout();
    auto I32Ty = Type::getInt32Ty(m_module->getContext());

    auto coffset = offset;
    gepIndexes.push_back(ConstantInt::get(I32Ty, 0));

    do {
        bool compositeType = false;

        if (curType->isStructTy()) {
            compositeType = true;
            StructType *curStructTy = dyn_cast<StructType>(curType);
            const StructLayout *curStructLayout = dataLayout.getStructLayout(curStructTy);

            auto curIdx = curStructLayout->getElementContainingOffset(coffset);

            gepIndexes.push_back(ConstantInt::get(I32Ty, curIdx));
            curType = curStructTy->getTypeAtIndex(curIdx);
            coffset -= curStructLayout->getElementOffset(curIdx);
        } else if (curType->isArrayTy()) {
            compositeType = true;
            ArrayType *curArrayTy = dyn_cast<ArrayType>(curType);
            auto elemSize = dataLayout.getTypeAllocSize(curArrayTy->getElementType());
            auto curIdx = coffset / elemSize;
            assert(curIdx < curArrayTy->getNumElements() && "Illegal field offset into CPUState!");

            gepIndexes.push_back(ConstantInt::get(I32Ty, curIdx));
            coffset %= elemSize;
            curType = curArrayTy->getElementType();
        }

        if (!compositeType) {
            // Offset may point in the middle of a structure/union, make sure
            // that the element size matches the requested size.
            auto typeSz = dataLayout.getTypeAllocSize(curType);
            return coffset == 0 && typeSz == sizeInBytes;
        }
    } while (true);

    return false;
}

bool TCGLLVMTranslator::GetStaticBranchTarget(const llvm::BasicBlock *BB, uint64_t *target) {
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

        // XXX: hard-coded pc index
        if (!go1->isZero() || go2->getZExtValue() != TCGLLVMTranslator::m_eip_last_gep_index) {
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

void tcg_llvm_close(void *l) {
    auto ctx = reinterpret_cast<TCGLLVMTranslator *>(l);
    delete ctx;
    tcg_llvm_translator = nullptr;
}

void *tcg_llvm_gen_code(void *l, TCGContext *s, TranslationBlock *tb) {
    auto ctx = reinterpret_cast<TCGLLVMTranslator *>(l);
    return ctx->generateCode(s, tb);
}
