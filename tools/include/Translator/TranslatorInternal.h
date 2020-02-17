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

#include <llvm-c/Core.h>
#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Linker/Linker.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Scalar/GVN.h>
#include <sstream>

#include "Translator.h"

#include "lib/Utils/Log.h"
#include "lib/Utils/Utils.h"

#include <tcg/tcg-llvm.h>

#include <cpu/i386/cpuid.h>

extern "C" {
#include <cpu-all.h>
#include <exec-all.h>
#include <qemu-common.h>
#include <tcg/tcg.h>
}

using namespace llvm;
namespace s2etools {

std::shared_ptr<const vmi::ExecutableFile> s_currentBinary;
bool Translator::s_translatorInited = false;
LogKey TranslatedBlock::TAG = LogKey("TranslatedBlock");
LogKey Translator::TAG = LogKey("Translator");
LogKey X86Translator::TAG = LogKey("X86Translator");

/*****************************************************************************
 * The following functions are invoked by the QEMU translator to read code.
 * This library redirects them to the binary file
 *****************************************************************************/
template <typename T> static T read_binary(off64_t offset) {
    T buf;
    if (s_currentBinary->read(&buf, sizeof(T), offset) != sizeof(T)) {
        throw InvalidAddressException(offset, sizeof(T));
    }
    return buf;
}

extern "C" {

int cpu_ldsb_code(CPUX86State *env, target_ulong ptr) {
    return (int) read_binary<int8_t>(ptr);
}

uint32_t cpu_ldub_code(CPUX86State *env, target_ulong ptr) {
    return read_binary<uint8_t>(ptr);
}

uint32_t cpu_lduw_code(CPUX86State *env, target_ulong ptr) {
    return read_binary<uint16_t>(ptr);
}

int cpu_ldsw_code(CPUX86State *env, target_ulong ptr) {
    return (int) (int16_t) read_binary<uint16_t>(ptr);
}

uint32_t cpu_ldl_code(CPUX86State *env, target_ulong ptr) {
    return read_binary<uint32_t>(ptr);
}

uint64_t cpu_ldq_code(CPUX86State *env, target_ulong ptr) {
    return read_binary<uint64_t>(ptr);
}

uint8_t helper_ldb_mmu_symb(CPUX86State *env, target_ulong addr, int mmu_idx, void *retaddr) {
    abort();
}

void helper_stb_mmu_symb(CPUX86State *env, target_ulong addr, uint8_t val, int mmu_idx, void *retaddr) {
    abort();
}

uint16_t helper_ldw_mmu_symb(CPUX86State *env, target_ulong addr, int mmu_idx, void *retaddr) {
    abort();
}

void helper_stw_mmu_symb(CPUX86State *env, target_ulong addr, uint16_t val, int mmu_idx, void *retaddr) {
    abort();
}

uint32_t helper_ldl_mmu_symb(CPUX86State *env, target_ulong addr, int mmu_idx, void *retaddr) {
    abort();
}

void helper_stl_mmu_symb(CPUX86State *env, target_ulong addr, uint32_t val, int mmu_idx, void *retaddr) {
    abort();
}

uint64_t helper_ldq_mmu_symb(CPUX86State *env, target_ulong addr, int mmu_idx, void *retaddr) {
    abort();
}

void helper_stq_mmu_symb(CPUX86State *env, target_ulong addr, uint64_t val, int mmu_idx, void *retaddr) {
    abort();
}
}

/*****************************************************************************/
void TranslatedBlock::print(llvm::raw_ostream &os) const {
    os << "TB at 0x" << hexval(m_address) << " type=0x" << m_type << " size=0x" << m_size << '\n';

    unsigned i = 0;
    for (auto const &successor : m_successors) {
        os << "succ[" << i << "]=0x" << hexval(successor) << '\n';
        ++i;
    }
    os << *m_function << '\n';
}

/*****************************************************************************/

using namespace llvm;

extern "C" {
void optimize_flags_init(void);
}

Translator::Translator(const std::string &bitcodeLibrary, const std::shared_ptr<vmi::ExecutableFile> binary) {
    m_binary = binary;
    s_currentBinary = binary;
    m_singlestep = false;

    if (s_translatorInited) {
        return;
    }

    tcg_exec_init(0);
    optimize_flags_init();

    m_ctx = TCGLLVMTranslator::create(bitcodeLibrary);

    s_translatorInited = true;
}

Translator::~Translator() {
    if (s_translatorInited) {
        delete m_ctx;
        s_translatorInited = false;
    }
}

llvm::Module *Translator::getModule() const {
    return m_ctx->getModule();
}

llvm::Function *Translator::createTbFunction(const std::string &name) const {
    return m_ctx->createTbFunction(name);
}

llvm::FunctionType *Translator::getTbType() const {
    return m_ctx->tbType();
}

void Translator::getRetInstructions(llvm::Function *f, llvm::SmallVector<llvm::ReturnInst *, 2> &ret) {
    foreach2 (it, f->begin(), f->end()) {
        BasicBlock &bb = *it;
        ReturnInst *ti = dyn_cast<ReturnInst>(bb.getTerminator());
        if (ti) {
            ret.push_back(ti);
        }
    }
}

unsigned Translator::getTargetPtrSizeInBytes() {
    return sizeof(target_ulong);
}

bool Translator::isGpRegister(llvm::Value *gepv, unsigned *regIndex) {
    if (!dyn_cast<GetElementPtrInst>(gepv)) {
        ConstantExpr *ce = dyn_cast<ConstantExpr>(gepv);
        if (!ce || (ce->getOpcode() != Instruction::GetElementPtr)) {
            return false;
        }
    }

    User *gep = dyn_cast<User>(gepv);

    if (gep->getNumOperands() != 4) {
        return false;
    }

    ConstantInt *c1 = dyn_cast<ConstantInt>(gep->getOperand(1));
    ConstantInt *c2 = dyn_cast<ConstantInt>(gep->getOperand(2));
    ConstantInt *c3 = dyn_cast<ConstantInt>(gep->getOperand(3));
    if (!c1 || !c2 || !c3) {
        return false;
    }

    bool isGp = !c1->getZExtValue() && !c2->getZExtValue();

    if (regIndex) {
        *regIndex = c3->getZExtValue();
    }

    return isGp;
}

bool Translator::isGpRegister(Value *gep, unsigned reg) {
    unsigned ret;
    bool b = isGpRegister(gep, &ret);
    if (!b) {
        return false;
    }
    return ret == reg;
}

bool Translator::isPcRegister(Value *gepv) {
    if (!dyn_cast<GetElementPtrInst>(gepv)) {
        ConstantExpr *ce = dyn_cast<ConstantExpr>(gepv);
        if (!ce || (ce->getOpcode() != Instruction::GetElementPtr)) {
            return false;
        }
    }

    User *gep = dyn_cast<User>(gepv);

    if (gep->getNumOperands() != 3) {
        return false;
    }

    ConstantInt *c1 = dyn_cast<ConstantInt>(gep->getOperand(1));
    ConstantInt *c2 = dyn_cast<ConstantInt>(gep->getOperand(2));
    if (!c1 || !c2) {
        return false;
    }

    return !c1->getZExtValue() && c2->getZExtValue() == 5;
}

void Translator::getWrappers(llvm::Module &M, MemoryWrappers &wrappers, const char **names) {
    for (unsigned i = 0; i < 4; ++i) {
        Function *f = M.getFunction(names[i]);
        assert(f);
        wrappers.push_back(f);
    }
}

void Translator::getStoreWrappers(llvm::Module &M, MemoryWrappers &wrappers) {
    const char *names[] = {"helper_stb_mmu", "helper_stw_mmu", "helper_stl_mmu", "helper_stq_mmu"};
    getWrappers(M, wrappers, names);
}

void Translator::getLoadWrappers(llvm::Module &M, MemoryWrappers &wrappers) {
    const char *names[] = {"helper_ldb_mmu", "helper_ldw_mmu", "helper_ldl_mmu", "helper_ldq_mmu"};
    getWrappers(M, wrappers, names);
}

Value *Translator::getPcPtr(IRBuilder<> &builder) {
    Module *m = builder.GetInsertBlock()->getParent()->getParent();
    LLVMContext &ctx = m->getContext();
    GlobalVariable *v = m->getGlobalVariable("myenv");
    Value *arg = builder.Insert(GetElementPtrInst::Create(nullptr, v, ConstantInt::get(ctx, APInt(64, 0))));

    SmallVector<Value *, 2> gepElements;
    gepElements.push_back(ConstantInt::get(m->getContext(), APInt(32, 0)));
    gepElements.push_back(ConstantInt::get(m->getContext(), APInt(32, 5)));
    return builder.CreateGEP(arg, ArrayRef<Value *>(gepElements.begin(), gepElements.end()));
}

Translator::RegisterMask Translator::getRegisterMaskForHelper(llvm::Function *helper) {
    Translator::RegisterMask mask;
    mask.rmask = -1;
    mask.wmask = -1;
    mask.accesses_mem = 1;
    return mask;
}

uint64_t Translator::getRegisterBitMask(llvm::Value *gepv) {
    if (!isGpRegister(gepv)) {
        return -1;
    }

    User *gep = dyn_cast<User>(gepv);

    ConstantInt *c1, *c2, *c3;
    c1 = c2 = c3 = NULL;

    c1 = dyn_cast<ConstantInt>(gep->getOperand(1));
    assert(c1 && c1->getZExtValue() == 0);

    c2 = dyn_cast<ConstantInt>(gep->getOperand(2));
    assert(c2);

    c3 = dyn_cast<ConstantInt>(gep->getOperand(3));

    if (c2->getZExtValue() == 0 && c3) {
        /* General purpose register */
        return 1LL << (c3->getZExtValue() + 5);
    }

    if (!c3 && c2->getZExtValue() < 5) {
        /* cc_op .. cc_tmp */
        return 1LL << (c2->getZExtValue() - 1);
    }

    assert(false && "Unsupported gep instruction");
    return 0;
}

/*****************************************************************************/

const char *X86Translator::s_regNames[8] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};

X86Translator::X86Translator(const std::string &bitcodeLibrary, const std::shared_ptr<vmi::ExecutableFile> binary)
    : Translator(bitcodeLibrary, binary) {
    m_functionPasses = new legacy::FunctionPassManager(m_ctx->getModule());
    m_functionPasses->add(createCFGSimplificationPass());

    // We need this passes to simplify the translation of the instruction.
    // The code is quite bulky, the fewer instructions, the better.
    m_functionOptPasses = new legacy::FunctionPassManager(m_ctx->getModule());
    // m_functionOptPasses->add(createVerifierPass());
    m_functionOptPasses->add(createDeadCodeEliminationPass());
    m_functionOptPasses->add(createGVNPass());
}

X86Translator::~X86Translator() {
    delete m_functionPasses;
    delete m_functionOptPasses;
}

static const uint64_t I486_FEATURES = (CPUID_FP87 | CPUID_VME | CPUID_PSE);

static const uint64_t PENTIUM_FEATURES =
    (I486_FEATURES | CPUID_DE | CPUID_TSC | CPUID_MSR | CPUID_MCE | CPUID_CX8 | CPUID_MMX | CPUID_APIC);

static const uint64_t PENTIUM2_FEATURES = (PENTIUM_FEATURES | CPUID_PAE | CPUID_SEP | CPUID_MTRR | CPUID_PGE |
                                           CPUID_MCA | CPUID_CMOV | CPUID_PAT | CPUID_PSE36 | CPUID_FXSR);

static const uint64_t PENTIUM3_FEATURES = (PENTIUM2_FEATURES | CPUID_SSE);

static const uint64_t PPRO_FEATURES =
    (CPUID_FP87 | CPUID_DE | CPUID_PSE | CPUID_TSC | CPUID_MSR | CPUID_MCE | CPUID_CX8 | CPUID_PGE | CPUID_CMOV |
     CPUID_PAT | CPUID_FXSR | CPUID_MMX | CPUID_SSE | CPUID_SSE2 | CPUID_PAE | CPUID_SEP | CPUID_APIC);

static const uint64_t EXT2_FEATURE_MASK = 0x0183F3FF;

static const uint64_t TCG_FEATURES =
    (CPUID_FP87 | CPUID_DE | CPUID_PSE | CPUID_TSC | CPUID_MSR | CPUID_PAE | CPUID_MCE | CPUID_CX8 | CPUID_APIC |
     CPUID_SEP | CPUID_MTRR | CPUID_PGE | CPUID_MCA | CPUID_CMOV | CPUID_PAT | CPUID_PSE36 | CPUID_CLFLUSH |
     CPUID_ACPI | CPUID_MMX | CPUID_FXSR | CPUID_SSE | CPUID_SSE2 | CPUID_SS);
/* partly implemented:
CPUID_MTRR, CPUID_MCA, CPUID_CLFLUSH (needed for Win64)
CPUID_PSE36 (needed for Solaris) */
/* missing:
CPUID_VME, CPUID_DTS, CPUID_SS, CPUID_HT, CPUID_TM, CPUID_PBE */

static const uint64_t TCG_EXT_FEATURES =
    (CPUID_EXT_SSE3 | CPUID_EXT_MONITOR | CPUID_EXT_CX16 | CPUID_EXT_POPCNT | CPUID_EXT_HYPERVISOR);
/* missing:
CPUID_EXT_DTES64, CPUID_EXT_DSCPL, CPUID_EXT_VMX, CPUID_EXT_EST,
CPUID_EXT_TM2, CPUID_EXT_XTPR, CPUID_EXT_PDCM, CPUID_EXT_XSAVE */

static const uint64_t TCG_EXT2_FEATURES = ((TCG_FEATURES & EXT2_FEATURE_MASK) | CPUID_EXT2_NX | CPUID_EXT2_MMXEXT |
                                           CPUID_EXT2_RDTSCP | CPUID_EXT2_3DNOW | CPUID_EXT2_3DNOWEXT);
/* missing:
CPUID_EXT2_PDPE1GB */
static const uint64_t TCG_EXT3_FEATURES =
    (CPUID_EXT3_LAHF_LM | CPUID_EXT3_SVM | CPUID_EXT3_CR8LEG | CPUID_EXT3_ABM | CPUID_EXT3_SSE4A);

TranslatedBlock *X86Translator::translate(uint64_t address, uint64_t lastAddress) {
    static uint8_t s_dummyBuffer[10 * 1024 * 1024];
    CPUArchState env;
    TranslationBlock *tb;

    if (!isInitialized()) {
        throw TranslatorNotInitializedException();
    }

    memset(&env, 0, sizeof(env));

    tb = tcg_tb_alloc(tcg_ctx);
    if (unlikely(tb == NULL)) {
        abort();
    }

    memset(tb, 0, sizeof(*tb));

    QTAILQ_INIT(&env.breakpoints);
    QTAILQ_INIT(&env.watchpoints);

    int codeSize;

    // We translate only one instruction at a time.
    // It is much easier to rebuild basic blocks this way.
    env.singlestep_enabled = isSingleStep();

    env.cpuid.cpuid_features = PPRO_FEATURES | CPUID_MTRR | CPUID_CLFLUSH | CPUID_MCA | CPUID_PSE36;

    env.cpuid.cpuid_ext_features = CPUID_EXT_SSE3 | CPUID_EXT_CX16 | CPUID_EXT_POPCNT;

    env.cpuid.cpuid_ext2_features =
        (PPRO_FEATURES & EXT2_FEATURE_MASK) | CPUID_EXT2_LM | CPUID_EXT2_SYSCALL | CPUID_EXT2_NX;

    env.cpuid.cpuid_ext3_features = CPUID_EXT3_LAHF_LM | CPUID_EXT3_SVM | CPUID_EXT3_ABM | CPUID_EXT3_SSE4A;

    env.generate_llvm = 1;

    env.eip = address;
    tb->pc = env.eip;
    tb->last_pc = lastAddress;
    tb->cs_base = 0;
    tb->tc.ptr = s_dummyBuffer;

    /* init jump list */
    tb->jmp_lock = SPIN_LOCK_UNLOCKED;
    tb->jmp_list_head = (uintptr_t) NULL;
    tb->jmp_list_next[0] = (uintptr_t) NULL;
    tb->jmp_list_next[1] = (uintptr_t) NULL;
    tb->jmp_dest[0] = (uintptr_t) NULL;
    tb->jmp_dest[1] = (uintptr_t) NULL;

    switch (getBinaryFile()->getPointerSize()) {
        case 4:
            tb->flags = (1 << HF_PE_SHIFT) | (1 << HF_CS32_SHIFT) | (1 << HF_SS32_SHIFT);
            break;

        case 8:
            tb->flags = (1 << HF_PE_SHIFT) | (1 << HF_CS32_SHIFT) | (1 << HF_SS32_SHIFT) | (1 << HF_CS64_SHIFT) |
                        (1 << HF_LMA_SHIFT);
            break;
        default:
            assert(false && "not implemented");
            break;
    }

    tb->flags |= 3 | HF_SOFTMMU_MASK | HF_OSFXSR_MASK; // CPL=3

    // May throw InvalidAddressException
    cpu_gen_code(&env, tb);

    LOGDEBUG(*(Function *) tb->llvm_function);

    LOGDEBUG("tb type: " << hexval(tb->se_tb_type) << "\n");

    ETranslatedBlockType bbType;
    switch (tb->se_tb_type) {
        case TB_DEFAULT:
            bbType = BB_DEFAULT;
            break;
        case TB_JMP:
            bbType = BB_JMP;
            break;
        case TB_JMP_IND:
            bbType = BB_JMP_IND;
            break;
        case TB_COND_JMP:
            bbType = BB_COND_JMP;
            break;
        case TB_COND_JMP_IND:
            bbType = BB_COND_JMP_IND;
            break;
        case TB_CALL:
            bbType = BB_CALL;
            break;
        case TB_CALL_IND:
            bbType = BB_CALL_IND;
            break;
        case TB_REP:
            bbType = BB_REP;
            break;
        case TB_RET:
            bbType = BB_RET;
            break;
        case TB_EXCP:
            bbType = BB_EXCP;
            break;
        case TB_INTERRUPT:
            bbType = BB_DEFAULT;
            break;
        default:
            assert(false && "Unsupported translation block type");
    }

    TCGLLVMTBInfo info = m_ctx->getTbInfo();

    /// Check if TB type matches number of static targets.
    /// Sometimes, we have things like mov eax, constant; jmp eax,
    /// which is reported as indirect jump, but really is a direct
    /// one. Need to handle this case.
    switch (tb->se_tb_type) {
        case TB_DEFAULT:
        case TB_JMP:
        case TB_CALL:
            if (info.staticBranchTargets.size() != 1) {
                LOGERROR("TB " << hexval(address) << " static targets mismatch TB type\n");
                return NULL;
            }
            break;

        case TB_COND_JMP:
        case TB_REP:
            if (info.staticBranchTargets.size() != 2) {
                LOGERROR("TB " << hexval(address) << " static targets mismatch TB type\n");
                return NULL;
            }
            break;

        case TB_JMP_IND:
        case TB_COND_JMP_IND:
        case TB_CALL_IND:

        case TB_RET:
        case TB_IRET:
        case TB_EXCP:
        case TB_SYSENTER:
            if (info.staticBranchTargets.size() != 0) {
                LOGERROR("TB " << hexval(address) << " static targets mismatch TB type\n");
                return NULL;
            }
            break;

        case TB_INTERRUPT:
            info.staticBranchTargets.clear();
            info.staticBranchTargets.push_back(tb->pc + tb->size);
            break;

        default:
            abort();
    }

    /* Make sure that we don't ask to translate a block that is actually shorter */
    if (tb->pcOfLastInstr != lastAddress) {
        /* XXX: sometimes TBs may be to big, QEMU stops translating when
           it runs out of buffer space. Could split the BB in multiple chunks. */
        LOGERROR("Translation didn't finish at bb end (" << hexval(tb->pcOfLastInstr) << " instead of "
                                                         << hexval(lastAddress) << ")\n");

        return NULL;
    }
    assert(tb->pcOfLastInstr == lastAddress);

    /* Handle call $+5 instructions, used to push the address of the next instruction */
    if (tb->se_tb_type == TB_CALL) {
        uint64_t target = info.staticBranchTargets[0];
        if (target == address + tb->size) {
            bbType = BB_DEFAULT;
            info.staticBranchTargets.clear();
        }
    }

    TranslatedBlock *ret = new TranslatedBlock(address, lastAddress, tb->size, (Function *) tb->llvm_function, bbType,
                                               info.staticBranchTargets, info.pcAssignments);

    m_functionPasses->run(*ret->getFunction());

    for (auto const &branchTarget : info.staticBranchTargets) {
        LOGDEBUG("Branch target: " << hexval(branchTarget) << "\n");
    }

    return ret;
}
} // namespace s2etools
