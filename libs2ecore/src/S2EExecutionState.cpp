///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
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

#include <s2e/cpu.h>

#include <s2e/FastReg.h>
#include <s2e/Plugin.h>
#include <s2e/S2EDeviceState.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>
#include <s2e/s2e_config.h>

#include <klee/Context.h>
#include <klee/Memory.h>
#include <klee/Solver.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/s2e_libcpu.h>

#include <klee/util/ExprPPrinter.h>
#include <llvm/Support/CommandLine.h>
#include <s2e/CorePlugin.h>

#include <tcg/tcg-llvm.h>

#include <iomanip>
#include <sstream>

namespace klee {
extern llvm::cl::opt<bool> DebugLogStateMerge;
}

namespace {
// CPUTLBEntry s_cputlb_empty_entry = { -1, -1, -1, -1, 0 };
}

extern llvm::cl::opt<bool> PrintModeSwitch;
extern llvm::cl::opt<bool> PrintForkingStatus;
extern llvm::cl::opt<bool> VerboseStateDeletion;
extern llvm::cl::opt<bool> DebugConstraints;

namespace s2e {

using namespace klee;

unsigned S2EExecutionState::s_lastSymbolicId = 0;

S2EExecutionState::S2EExecutionState(klee::KFunction *kf)
    : klee::ExecutionState(kf), m_stateID(g_s2e->fetchAndIncrementStateId()), m_startSymbexAtPC((uint64_t) -1),
      m_active(true), m_zombie(false), m_yielded(false), m_runningConcrete(true), m_pinned(false),
      m_isStateSwitchForbidden(false), m_deviceState(this), m_asCache(&addressSpace),
      m_registers(&m_active, &m_runningConcrete, this, this), m_memory(), m_lastS2ETb(nullptr),
      m_needFinalizeTBExec(false), m_forkAborted(false), m_nextSymbVarId(0), m_tlb(&m_asCache, &m_registers),
      m_runningExceptionEmulationCode(false) {
    // XXX: make this a struct, not a pointer...
    m_timersState = new TimersState;
    m_guid = m_stateID;
}

S2EExecutionState::~S2EExecutionState() {
    PluginStateMap::iterator it;

    if (VerboseStateDeletion) {
        g_s2e->getDebugStream() << "Deleting state " << m_stateID << " " << this << '\n';
    }

    // print_stacktrace();

    for (it = m_PluginState.begin(); it != m_PluginState.end(); ++it) {
        delete it->second;
    }

    g_s2e->refreshPlugins();

    // XXX: This cannot be done, as device states may refer to each other
    // delete m_deviceState;

    delete m_timersState;
}

void S2EExecutionState::assignGuid(uint64_t guid) {
    m_guid = guid;
}

/***/

ExecutionState *S2EExecutionState::clone() {
    // When cloning, all ObjectState becomes not owned by neither of states
    // This means that we must clean owned-by-us flag in S2E TLB
    assert(m_active);

    m_tlb.clearTlbOwnership();
#if defined(SE_ENABLE_PHYSRAM_TLB)
    m_tlb.clearRamTlb();
#endif

    S2EExecutionState *ret = new S2EExecutionState(*this);
    ret->addressSpace.state = ret;
    ret->m_deviceState.setExecutionState(ret);
    ret->concolics = Assignment::create(true);
    ret->m_lastS2ETb = m_lastS2ETb;

    ret->m_stateID = g_s2e->fetchAndIncrementStateId();
    ret->m_guid = ret->m_stateID;

    ret->m_timersState = new TimersState;
    *ret->m_timersState = *m_timersState;

    // Clone the plugins
    PluginStateMap::iterator it;
    ret->m_PluginState.clear();
    for (it = m_PluginState.begin(); it != m_PluginState.end(); ++it) {
        ret->m_PluginState.insert(std::make_pair((*it).first, (*it).second->clone()));
    }

    ret->m_tlb.assignNewState(&ret->m_asCache, &ret->m_registers);

    ret->m_registers.update(ret->addressSpace, &ret->m_active, &ret->m_runningConcrete, ret, ret);

    ret->m_asCache.update(&ret->addressSpace);

    m_registers.update(addressSpace, &m_active, &m_runningConcrete, this, this);

    m_memory.update(&addressSpace, &m_asCache, &m_active, this, this);
    ret->m_memory.update(&ret->addressSpace, &ret->m_asCache, &ret->m_active, ret, ret);

    return ret;
}

/***/

void S2EExecutionState::enableForking() {
    if (!forkDisabled) {
        return;
    }

    forkDisabled = false;

    if (PrintForkingStatus) {
        g_s2e->getInfoStream(this) << "Enabled forking"
                                   << " at pc = " << (void *) regs()->getPc()
                                   << " and pagedir = " << hexval(regs()->getPageDir()) << '\n';
    }
}

void S2EExecutionState::disableForking() {
    if (forkDisabled) {
        return;
    }

    forkDisabled = true;

    if (PrintForkingStatus) {
        g_s2e->getInfoStream(this) << "Disabled forking"
                                   << " at pc = " << (void *) regs()->getPc()
                                   << " and pagedir = " << hexval(regs()->getPageDir()) << '\n';
    }
}

void S2EExecutionState::switchToConcrete() {
    assert(!m_runningConcrete);

    if (PrintModeSwitch) {
        g_s2e->getInfoStream(this) << "Switching to concrete execution at pc = " << hexval(regs()->getPc()) << '\n';
    }

    // assert(os->isAllConcrete());
    m_registers.copySymbRegs(true);

    m_runningConcrete = true;
}

void S2EExecutionState::switchToSymbolic() {
    assert(m_runningConcrete);

    if (PrintModeSwitch) {
        g_s2e->getInfoStream(this) << "Switching to symbolic execution at pc = " << hexval(regs()->getPc()) << '\n';
    }

    // assert(os && os->isAllConcrete());

    // TODO: check that symbolic registers were not accessed
    // in shared location ! Ideas: use hw breakpoints, or instrument
    // translated code.

    m_registers.copySymbRegs(false);
    m_runningConcrete = false;
}

// This function must be called just after the machine call instruction
// was executed.
// XXX: assumes x86 architecture.
bool S2EExecutionState::bypassFunction(unsigned paramCount) {
    uint64_t retAddr;
    if (!getReturnAddress(&retAddr)) {
        return false;
    }

    uint64_t newSp = regs()->getSp() + (paramCount + 1) * getPointerSize();

    regs()->setSp(newSp);
    regs()->setPc(retAddr);
    return true;
}

// May be called right after the machine call instruction
// XXX: assumes x86 architecture
bool S2EExecutionState::getReturnAddress(uint64_t *retAddr) {
    unsigned ptrSize = getPointerSize();
    if (ptrSize == 4) {
        uint32_t ra;
        if (!mem()->read(regs()->getSp(), &ra, sizeof(ra))) {
            return false;
        }
        *retAddr = ra;
    } else if (ptrSize == 8) {
        if (!mem()->read(regs()->getSp(), retAddr, sizeof(*retAddr))) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

TranslationBlock *S2EExecutionState::getTb() const {
    return (TranslationBlock *) s2e_read_register_concrete_fast<uintptr_t>(CPU_OFFSET(se_current_tb));
}

/***/

// The var names may end up in the SMTLIB2 queries and the solver
// will throw parse errors if there are any special characters,
// therefore, convert everything to alphanumerical.
std::string S2EExecutionState::getUniqueVarName(const std::string &name, std::string &rawVar) {
    std::stringstream ss;

    ss << "v" << (m_nextSymbVarId++) << "_" << name << "_" << s_lastSymbolicId;
    s_lastSymbolicId++;

    std::string original = ss.str();
    std::string filtered = ss.str();

    for (unsigned i = 0; i < filtered.size(); ++i) {
        if (!isalnum(filtered[i]) && filtered[i] != '_') {
            filtered[i] = '_';
        }
    }

    rawVar = original;
    return filtered;
}

ref<Expr> S2EExecutionState::createSymbolicValue(const std::string &name, Expr::Width width,
                                                 const std::vector<unsigned char> &buffer) {
#ifdef CONFIG_SYMBEX_MP
    std::string originalVarName;
    std::string sname = getUniqueVarName(name, originalVarName);

    unsigned bytes = Expr::getMinBytesForWidth(width);
    unsigned bufferSize = buffer.size();

    assert((bufferSize == bytes || bufferSize == 0) &&
           "Concrete buffer must either have the same size as the expression or be empty");

    auto array = Array::create(sname, bytes, nullptr, nullptr, name);

    symbolics.push_back(array);

    if (bufferSize == bytes) {
        concolics->add(array, buffer);
    }

    ref<Expr> ret = ReadExpr::createTempRead(array, width);

    g_s2e->getCorePlugin()->onSymbolicVariableCreation.emit(this, name, {ret}, array);

    return ret;
#else
    g_s2e->getWarningsStream(this) << "Cannot create symbolic data in single-path (s2e_sp) build\n";

    unsigned i;
    uint64_t value = 0;
    for (i = 0; i < buffer.size(); i++) {
        value = value + (buffer[i] << (i * 8));
    }
    return ConstantExpr::create(value, width);
#endif
}

ref<Expr> S2EExecutionState::createSymbolicValue(const std::string &name, Expr::Width width) {
    std::vector<unsigned char> concreteValues;

    unsigned bytes = Expr::getMinBytesForWidth(width);
    for (unsigned i = 0; i < bytes; ++i) {
        concreteValues.push_back(0);
    }

    return createSymbolicValue(name, width, concreteValues);
}

std::vector<ref<Expr>> S2EExecutionState::createSymbolicArray(const std::string &name, unsigned size,
                                                              const std::vector<unsigned char> &concreteBuffer,
                                                              std::string *varName) {
    assert(concreteBuffer.size() == size || concreteBuffer.size() == 0);

    std::string originalVarName;
    std::string sname = getUniqueVarName(name, originalVarName);
    if (varName) {
        *varName = sname;
    }

    auto array = Array::create(sname, size, nullptr, nullptr, name);

    auto ul = UpdateList::create(array, 0);

    std::vector<ref<Expr>> result;
    result.reserve(size);
#ifdef CONFIG_SYMBEX_MP
    for (unsigned i = 0; i < size; ++i) {
        result.push_back(ReadExpr::create(ul, ConstantExpr::alloc(i, Expr::Int32)));
    }

    // Add it to the set of symbolic expressions, to be able to generate
    // test cases later.
    // Dummy memory object
    symbolics.push_back(array);

    if (concreteBuffer.size() == size) {
        concolics->add(array, concreteBuffer);
    }

    g_s2e->getCorePlugin()->onSymbolicVariableCreation.emit(this, name, result, array);
#else
    g_s2e->getWarningsStream(this) << "Cannot create symbolic data in single-path (s2e_sp) build\n";

    for (unsigned i = 0; i < size; ++i) {
        result.push_back(ConstantExpr::create(concreteBuffer[i], Expr::Int8));
    }
#endif
    return result;
}

std::vector<ref<Expr>> S2EExecutionState::createSymbolicArray(const std::string &name, unsigned size,
                                                              std::string *varName) {
    std::vector<unsigned char> concreteBuffer;

    for (unsigned i = 0; i < size; ++i) {
        concreteBuffer.push_back(0);
    }

    return createSymbolicArray(name, size, concreteBuffer, varName);
}

/***/

// Must be called right after the machine call instruction is executed.
// This function will reexecute the call but in symbolic mode
// XXX: remove circular references with executor?
void S2EExecutionState::undoCallAndJumpToSymbolic() {
    if (needToJumpToSymbolic()) {
        // Undo the call
        target_ulong size = sizeof(uint32_t);
#ifdef TARGET_X86_64
        if (env->hflags & HF_CS64_MASK) {
            size = sizeof(target_ulong);
        }
#endif
        assert(getTb()->pcOfLastInstr);
        regs()->setSp(regs()->getSp() + size);
        regs()->setPc(getTb()->pcOfLastInstr);
        jumpToSymbolicCpp();
    }
}

void S2EExecutionState::jumpToSymbolicCpp() {
    if (!isRunningConcrete()) {
        return;
    }
    m_toRunSymbolically.insert(std::make_pair(regs()->getPc(), regs()->getPageDir()));
    m_startSymbexAtPC = regs()->getPc();

    // XXX: how to make this cleaner?
    g_s2e->getExecutor()->updateConcreteFastPath(this);

    // XXX: what about regs_to_env ?
    throw CpuExitException();
}

void S2EExecutionState::jumpToSymbolic() {
    assert(isActive() && isRunningConcrete());

    m_toRunSymbolically.insert(std::make_pair(regs()->getPc(), regs()->getPageDir()));
    m_startSymbexAtPC = regs()->getPc();

    // XXX: how to make this cleaner?
    g_s2e->getExecutor()->updateConcreteFastPath(this);

    // XXX: what about regs_to_env ?
    longjmp(env->jmp_env, 1);
}

bool S2EExecutionState::needToJumpToSymbolic() const {
    return isRunningConcrete();
}

void S2EExecutionState::yield() {
    g_s2e->getInfoStream(this) << "Yielding state " << getID() << "\n";

    setYieldState(true);

    // Stop current execution
    regs()->write<int>(CPU_OFFSET(exception_index), EXCP_SE);
    throw CpuExitException();
}

/***/

bool S2EExecutionState::merge(const ExecutionState &_b) {
    assert(dynamic_cast<const S2EExecutionState *>(&_b));
    const S2EExecutionState &b = static_cast<const S2EExecutionState &>(_b);

    assert(!m_active && !b.m_active);

    llvm::raw_ostream &s = g_s2e->getInfoStream(this);

    if (DebugLogStateMerge) {
        s << "Attempting merge with state " << b.getID() << '\n';
    }

    /* Check CPUArchState */
    {
        if (m_registers.compareArchitecturalConcreteState(b.m_registers)) {
            if (DebugLogStateMerge) {
                s << "merge failed: different concrete cpu state" << '\n';
            }
            return false;
        }
    }

    if (!ExecutionState::merge(b)) {
        return false;
    }

    // Merge dirty mask by clearing bits that differ. Clearning bits in
    // dirty mask can only affect performance but not correcntess.
    // NOTE: this requires flushing TLB
    {
        auto &dirtyMask = S2EExecutionStateMemory::getDirtyMask();
        auto os = addressSpace.findObject(dirtyMask.address);
        auto wos = addressSpace.getWriteable(os);
        uint8_t *dirtyMaskA = wos->getConcreteBuffer();
        const uint8_t *dirtyMaskB = b.addressSpace.findObject(dirtyMask.address)->getConcreteBuffer();

        for (unsigned i = 0; i < dirtyMask.size; ++i) {
            if (dirtyMaskA[i] != dirtyMaskB[i]) {
                dirtyMaskA[i] = 0;
            }
        }
    }

    return true;
}

void S2EExecutionState::enumPossibleRanges(ref<Expr> e, ref<Expr> start, ref<Expr> end, std::vector<Range> &ranges) {
    ArrayVec symbObjects = symbolics;
    solver()->getRanges(constraints(), symbObjects, e, start, end, ranges);
}

/***/

/// \brief Try to solve additional state constraints
///
/// Find solution for merged original state constraints and
/// supplied additional constraints.
///
/// \param c additional constraints
/// \param newConstraints merged constraints will be saved here, can be nullptr
/// \param newConcolics computed concolic values will be saved here, can be nullptr
/// \return true if solution exists
///
bool S2EExecutionState::testConstraints(const std::vector<ref<Expr>> &c, ConstraintManager *newConstraints,
                                        Assignment *newConcolics) {
#ifdef CONFIG_SYMBEX_MP
    ConstraintManager tmpConstraints = constraints();
    foreach2 (it, c.begin(), c.end()) {
        s2e_assert(this, !(isa<ConstantExpr>(*it) && dyn_cast<ConstantExpr>(*it)->isFalse()),
                   "Attempt to add invalid (false) constraint");
        tmpConstraints.addConstraint(*it);
    }

    ArrayVec symbObjects = symbolics;

    std::vector<std::vector<unsigned char>> concreteObjects;
    if (!solver()->getInitialValues(Query(tmpConstraints, ConstantExpr::create(0, Expr::Bool)), symbObjects,
                                    concreteObjects)) {
        return false;
    }

    if (newConstraints) {
        *newConstraints = tmpConstraints;
    }
    if (newConcolics) {
        newConcolics->clear();
        for (unsigned i = 0; i < symbObjects.size(); ++i) {
            newConcolics->add(symbObjects[i], concreteObjects[i]);
        }
    }
#endif

    return true;
}

/***/

uint64_t S2EExecutionState::concretize(klee::ref<klee::Expr> expression, const std::string &reason, bool silent) {
#ifdef CONFIG_SYMBEX_MP
    if (silent) {
        return this->toConstantSilent(expression)->getZExtValue();
    } else {
        return this->toConstant(expression, reason.c_str())->getZExtValue();
    }
#else
    ConstantExpr *ce = dyn_cast<ConstantExpr>(expression);
    assert(ce && "Expression must be constant here");
    return ce->getZExtValue();
#endif
}

void S2EExecutionState::addressSpaceChange(const klee::ObjectKey &key, const klee::ObjectStateConstPtr &oldState,
                                           const klee::ObjectStatePtr &newState) {

    if (m_registers.addressSpaceChange(key, oldState, newState)) {
        goto end;
    }

    if (m_tlb.addressSpaceChangeUpdateTlb(oldState, newState)) {
        goto end;
    }

end:
    g_s2e->getCorePlugin()->onAddressSpaceChange.emit(this, key, oldState, newState);
}

void S2EExecutionState::addressSpaceSymbolicStatusChange(const ObjectStatePtr &object, bool becameConcrete) {
    // Deal with CPU registers
    g_s2e->getExecutor()->updateConcreteFastPath(this);

    // Deal with RAM
    if (object->getBitArraySize() != SE_RAM_OBJECT_SIZE) {
        return;
    }

    auto obj = m_asCache.getBaseObject(object);
    m_tlb.updateTlb(obj, obj);
}

void S2EExecutionState::addressSpaceObjectSplit(const ObjectStateConstPtr &oldObject,
                                                const std::vector<ObjectStatePtr> &newObjects) {
    // Splitting can only happen to RAM
    auto baseObject = m_asCache.notifySplit(oldObject, newObjects);
    m_tlb.updateTlb(oldObject, baseObject);
}

uint64_t S2EExecutionState::readMemIoVaddr(bool masked) {
    klee::ref<klee::Expr> result;

    if (m_memIoVaddr.isNull()) {
        return env->mem_io_vaddr;
    }

    if (masked) {
        result = AndExpr::create(m_memIoVaddr,
                                 klee::ConstantExpr::create((target_ulong) TARGET_PAGE_MASK, m_memIoVaddr->getWidth()));
        // This assumes that the page is already fully constrained by the MMU
        result = concolics->evaluate(result);
        assert(dyn_cast<ConstantExpr>(result) && "Expression must be constant here");
    } else {
        result = m_memIoVaddr;
        result = this->toConstant(result, "Reading mem_io_vaddr");
    }

    ConstantExpr *ce = dyn_cast<ConstantExpr>(result);
    assert(ce && "Expression must be constant here");
    return ce->getZExtValue();
}

bool S2EExecutionState::getStaticTarget(uint64_t *target) {
    if (stack.size() == 1) {
        return false;
    }

    const llvm::Instruction *instr = pc->inst;
    const llvm::BasicBlock *BB = instr->getParent();
    if (!TCGLLVMTranslator::GetStaticBranchTarget(BB, target)) {
        return false;
    }

    return true;
}

/**
 * Attempts to retrieve the static branch destination of the state.
 * Useful to decide where the state is going to branch on fork.
 * Should be called from onStateFork event.
 * TODO: move this to the translator?
 */
bool S2EExecutionState::getStaticBranchTargets(uint64_t *truePc, uint64_t *falsePc) {
    if (stack.size() == 1) {
        return false;
    }

    const llvm::Instruction *instr = pc->inst;

    // Check whether we are the first instruction of the block.
    const llvm::BasicBlock *BB = instr->getParent();
    if (instr != &*BB->begin()) {
        return false;
    }

    // There can be only one predecessor jumping to the terminating block (xxx: check this)
    const llvm::BasicBlock *PredBB = BB->getSinglePredecessor();
    if (!PredBB) {
        return false;
    }

    // We came here via a branch instruction
    const llvm::BranchInst *Bi = dyn_cast<llvm::BranchInst>(PredBB->getTerminator());
    if (!Bi) {
        return false;
    }

    const llvm::BasicBlock *trueBB = Bi->getSuccessor(0);
    const llvm::BasicBlock *falseBB = Bi->getSuccessor(1);

    const llvm::BasicBlock *succs[2];
    uint64_t results[2] = {0, 0};
    unsigned resCount = 0;
    succs[0] = trueBB;
    succs[1] = falseBB;

    for (unsigned i = 0; i < 2; ++i) {
        BB = succs[i];
        if (!TCGLLVMTranslator::GetStaticBranchTarget(BB, &results[i])) {
            return false;
        }
        ++resCount;
    }

    if (resCount != 2) {
        return false;
    }

    *truePc = results[0];
    *falsePc = results[1];

    return true;
}

unsigned S2EExecutionState::getPointerSize() const {
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    TranslationBlock *tb = getTb();
    bool is32 = (tb->flags >> HF_CS32_SHIFT) & 1;
    bool is64 = (tb->flags >> HF_CS64_SHIFT) & 1;
    if (is64) {
        return 8;
    } else if (is32) {
        return 4;
    } else {
        return 2;
    }
#elif defined(TARGET_ARM)
    return 4;
#else
#error Unsupported target architecture
#endif
}

static int __disas_print(FILE *fp, const char *fmt, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, fmt);
    int ret = vsnprintf(buffer, sizeof(buffer) - 1, fmt, args);
    va_end(args);

    llvm::raw_ostream *os = reinterpret_cast<llvm::raw_ostream *>(fp);
    *os << buffer;
    return ret;
}

bool S2EExecutionState::disassemble(llvm::raw_ostream &os, uint64_t pc, unsigned size) {
    if (!getTb()) {
        return false;
    }

    return disassemble(os, pc, size, getPointerSize());
}

bool S2EExecutionState::disassemble(llvm::raw_ostream &os, uint64_t pc, unsigned size, unsigned pointerSize) {
    int flags = 0; // 32-bit code by default
    switch (getPointerSize()) {
        case 4:
            flags = 0;
            break;
        case 8:
            flags = 2;
            break;
        default:
            return false;
    }

    FILE *fp = reinterpret_cast<FILE *>(&os);
    auto ret = target_disas_ex(regs()->getCpuState(), fp, __disas_print, pc, size, flags);
    return !ret;
}

} // namespace s2e

/******************************************/
/* Functions for the s2e-libcpu interface */

extern "C" {

s2e::S2EExecutionState *g_s2e_state = nullptr;

int s2e_is_zombie() {
    return g_s2e_state->isZombie();
}

int s2e_is_yielded() {
    return g_s2e_state->isYielded();
}

int s2e_is_running_concrete() {
    return g_s2e_state->isRunningConcrete();
}

int s2e_is_runnable() {
    return !s2e_is_zombie() && !s2e_is_yielded();
}

void s2e_reset_state_switch_timer(void) {
    g_s2e->getExecutor()->resetStateSwitchTimer();
}

void s2e_read_register_concrete(unsigned offset, uint8_t *buf, unsigned size) {
    g_s2e_state->regs()->read(offset, buf, size, true);
}

void s2e_write_register_concrete(unsigned offset, uint8_t *buf, unsigned size) {
    g_s2e_state->regs()->write(offset, buf, size);
}

uint8_t se_read_dirty_mask(uint64_t host_address) {
    return g_s2e_state->mem()->readDirtyMask(host_address);
}

void se_write_dirty_mask(uint64_t host_address, uint8_t val) {
    return g_s2e_state->mem()->writeDirtyMask(host_address, val);
}

static inline CPUTLBRAMEntry *s2e_get_ram_tlb_entry(uint64_t host_address) {
#if defined(SE_ENABLE_PHYSRAM_TLB)
    uintptr_t tlb_index = (host_address >> 12) & (CPU_TLB_SIZE - 1);
    CPUArchState *env = g_s2e_state->regs()->getCpuState();
    return &env->se_ram_tlb[tlb_index];
#else
    return nullptr;
#endif
}

#ifdef SE_ENABLE_PHYSRAM_TLB
static inline void s2e_dma_rw(uint64_t hostAddress, uint8_t *buf, unsigned size, bool is_write) {
    while (size > 0) {
        uint64_t hostPage = hostAddress & SE_RAM_OBJECT_MASK;
        uint64_t length = (hostPage + SE_RAM_OBJECT_SIZE) - hostAddress;
        if (length > size) {
            length = size;
        }

        CPUTLBRAMEntry *te = s2e_get_ram_tlb_entry(hostAddress);

        if (te->host_page == hostPage) {
            if (is_write) {
                klee::ObjectStateConstPtr os = static_cast<const klee::ObjectState *>(te->object_state);
                os = g_s2e_state->addressSpace.getWriteable(os);
                assert(!(te->host_page & TLB_NOT_OURS));
            }

            void *ptr = (void *) (hostAddress + te->addend);
            if (is_write) {
                memcpy(ptr, buf, length);
            } else {
                memcpy(buf, ptr, length);
            }
        } else {
            // Populate the TLB with a 1-byte transfer
            g_s2e_state->mem()->transferRam(te, hostAddress, buf, 1, is_write, false, false);
            length = 1;
        }

        buf = (uint8_t *) buf + length;
        hostAddress += length;
        size -= length;
    }
}
#endif

void s2e_dma_read(uint64_t hostAddress, uint8_t *buf, unsigned size) {
#if defined(SE_ENABLE_PHYSRAM_TLB)
    s2e_dma_rw(hostAddress, buf, size, false);
#else
    g_s2e_state->mem()->read(hostAddress, buf, size, s2e::HostAddress);
#endif
}

void s2e_dma_write(uint64_t hostAddress, uint8_t *buf, unsigned size) {
#if defined(SE_ENABLE_PHYSRAM_TLB)
    s2e_dma_rw(hostAddress, buf, size, true);
#else
    g_s2e_state->mem()->write(hostAddress, buf, size, s2e::HostAddress);
#endif
}

void s2e_read_ram_concrete_check(uint64_t host_address, uint8_t *buf, uint64_t size) {
    assert(g_s2e_state->isRunningConcrete());
    CPUTLBRAMEntry *re = s2e_get_ram_tlb_entry(host_address);
    g_s2e_state->mem()->transferRam(re, host_address, buf, size, false, true, false);
}

void s2e_read_ram_concrete(uint64_t host_address, void *buf, uint64_t size) {
#ifdef CONFIG_SYMBEX_MP
    CPUTLBRAMEntry *re = s2e_get_ram_tlb_entry(host_address);
    g_s2e_state->mem()->transferRam(re, host_address, static_cast<uint8_t *>(buf), size, false, false, false);
#else
    memcpy(buf, (const void *) host_address, size);
#endif
}

void s2e_write_ram_concrete(uint64_t host_address, const uint8_t *buf, uint64_t size) {
#ifdef CONFIG_SYMBEX_MP
    CPUTLBRAMEntry *re = s2e_get_ram_tlb_entry(host_address);
    g_s2e_state->mem()->transferRam(re, host_address, const_cast<uint8_t *>(buf), size, true, false, false);
#else
    memcpy((void *) host_address, buf, size);
#endif
}

// To be used by GDB scripts to convert addresses
uint64_t s2e_host_to_state_address(uint64_t hostaddr) {
    return (uint64_t) g_s2e_state->mem()->getConcreteBuffer(hostaddr, s2e::HostAddress);
}

} // extern "C"
