///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
extern llvm::cl::opt<bool> ConcolicMode;
extern llvm::cl::opt<bool> VerboseStateDeletion;
extern llvm::cl::opt<bool> DebugConstraints;

namespace s2e {

using namespace klee;

unsigned S2EExecutionState::s_lastSymbolicId = 0;

S2EExecutionState::S2EExecutionState(klee::KFunction *kf)
    : klee::ExecutionState(kf), m_stateID(g_s2e->fetchAndIncrementStateId()), m_symbexEnabled(true),
      m_startSymbexAtPC((uint64_t) -1), m_active(true), m_zombie(false), m_yielded(false), m_runningConcrete(true),
      m_pinned(false), m_isStateSwitchForbidden(false), m_deviceState(this), m_asCache(&addressSpace),
      m_registers(&m_active, &m_runningConcrete, this, this), m_memory(), m_lastS2ETb(NULL),
      m_needFinalizeTBExec(false), m_forkAborted(false), m_nextSymbVarId(0), m_tlb(&m_asCache, &m_registers),
      m_runningExceptionEmulationCode(false) {
    // XXX: make this a struct, not a pointer...
    m_timersState = new TimersState;
}

S2EExecutionState::~S2EExecutionState() {
    assert(m_lastS2ETb == NULL);

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
    ret->concolics = new Assignment(true);

    if (m_lastS2ETb) {
        g_s2e->getExecutor()->refS2ETb(m_lastS2ETb);
    }

    ret->m_stateID = g_s2e->fetchAndIncrementStateId();

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

void S2EExecutionState::enableSymbolicExecution() {
    if (m_symbexEnabled) {
        return;
    }

    m_symbexEnabled = true;

    g_s2e->getInfoStream(this) << "Enabled symbex"
                               << " at pc = " << (void *) getPc() << " and pagedir = " << hexval(getPageDir()) << '\n';
}

void S2EExecutionState::disableSymbolicExecution() {
    if (!m_symbexEnabled) {
        return;
    }

    m_symbexEnabled = false;

    g_s2e->getInfoStream(this) << "Disabled symbex"
                               << " at pc = " << (void *) getPc() << " and pagedir = " << hexval(getPageDir()) << '\n';
}

void S2EExecutionState::enableForking() {
    if (!forkDisabled) {
        return;
    }

    forkDisabled = false;

    if (PrintForkingStatus) {
        g_s2e->getInfoStream(this) << "Enabled forking"
                                   << " at pc = " << (void *) getPc() << " and pagedir = " << hexval(getPageDir())
                                   << '\n';
    }
}

void S2EExecutionState::disableForking() {
    if (forkDisabled) {
        return;
    }

    forkDisabled = true;

    if (PrintForkingStatus) {
        g_s2e->getInfoStream(this) << "Disabled forking"
                                   << " at pc = " << (void *) getPc() << " and pagedir = " << hexval(getPageDir())
                                   << '\n';
    }
}

// This function must be called just after the machine call instruction
// was executed.
// XXX: assumes x86 architecture.
bool S2EExecutionState::bypassFunction(unsigned paramCount) {
    uint64_t retAddr;
    if (!getReturnAddress(&retAddr)) {
        return false;
    }

    uint64_t newSp = getSp() + (paramCount + 1) * getPointerSize();

    setSp(newSp);
    setPc(retAddr);
    return true;
}

// May be called right after the machine call instruction
// XXX: assumes x86 architecture
bool S2EExecutionState::getReturnAddress(uint64_t *retAddr) {
    unsigned ptrSize = getPointerSize();
    if (ptrSize == 4) {
        uint32_t ra;
        if (!mem()->readMemoryConcrete(regs()->getSp(), &ra, sizeof(ra))) {
            return false;
        }
        *retAddr = ra;
    } else if (ptrSize == 8) {
        if (!mem()->readMemoryConcrete(regs()->getSp(), retAddr, sizeof(*retAddr))) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

TranslationBlock *S2EExecutionState::getTb() const {
    return s2e_read_register_concrete_fast<TranslationBlock *>(CPU_OFFSET(se_current_tb));
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

ref<Expr> S2EExecutionState::createConcolicValue(const std::string &name, Expr::Width width,
                                                 const std::vector<unsigned char> &buffer) {
#ifdef CONFIG_SYMBEX_MP
    std::string originalVarName;
    std::string sname = getUniqueVarName(name, originalVarName);

    unsigned bytes = Expr::getMinBytesForWidth(width);
    unsigned bufferSize = buffer.size();

    assert((bufferSize == bytes || bufferSize == 0) &&
           "Concrete buffer must either have the same size as the expression or be empty");

    const Array *array = new Array(sname, bytes, NULL, NULL, name);

    MemoryObject *mo = new MemoryObject(0, bytes, false, false, false, NULL);
    mo->setName(sname);

    symbolics.push_back(std::make_pair(mo, array));

    if (bufferSize == bytes) {
        if (ConcolicMode) {
            concolics->add(array, buffer);
        } else {
            g_s2e->getWarningsStream(this) << "Concolic mode disabled: ignoring concrete assignments for " << name
                                           << '\n';
        }
    }

    variableNameMapping = variableNameMapping.insert(std::make_pair(sname, originalVarName));

    ref<Expr> ret = Expr::createTempRead(array, width);

    g_s2e->getCorePlugin()->onSymbolicVariableCreation.emit(this, name, {ret}, mo, array);

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

    if (ConcolicMode) {
        unsigned bytes = Expr::getMinBytesForWidth(width);
        for (unsigned i = 0; i < bytes; ++i) {
            concreteValues.push_back(0);
        }
    }

    return createConcolicValue(name, width, concreteValues);
}

std::vector<ref<Expr>> S2EExecutionState::createConcolicArray(const std::string &name, unsigned size,
                                                              const std::vector<unsigned char> &concreteBuffer,
                                                              std::string *varName) {
    assert(concreteBuffer.size() == size || concreteBuffer.size() == 0);

    std::string originalVarName;
    std::string sname = getUniqueVarName(name, originalVarName);
    if (varName) {
        *varName = sname;
    }

    const Array *array = new Array(sname, size, NULL, NULL, name);

    UpdateList ul(array, 0);

    std::vector<ref<Expr>> result;
    result.reserve(size);
#ifdef CONFIG_SYMBEX_MP
    for (unsigned i = 0; i < size; ++i) {
        result.push_back(ReadExpr::create(ul, ConstantExpr::alloc(i, Expr::Int32)));
    }

    // Add it to the set of symbolic expressions, to be able to generate
    // test cases later.
    // Dummy memory object
    MemoryObject *mo = new MemoryObject(0, size, false, false, false, NULL);
    mo->setName(sname);

    symbolics.push_back(std::make_pair(mo, array));

    if (concreteBuffer.size() == size) {
        if (ConcolicMode) {
            concolics->add(array, concreteBuffer);
        } else {
            g_s2e->getWarningsStream(this) << "Concolic mode disabled: ignoring concrete assignments for " << name
                                           << '\n';
        }
    }

    g_s2e->getCorePlugin()->onSymbolicVariableCreation.emit(this, name, result, mo, array);
    variableNameMapping = variableNameMapping.insert(std::make_pair(sname, originalVarName));
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

    if (ConcolicMode) {
        for (unsigned i = 0; i < size; ++i) {
            concreteBuffer.push_back(0);
        }
    }

    return createConcolicArray(name, size, concreteBuffer, varName);
}

/*
 * Read bytes from this state given a KLEE address.
 * Optionally store the result in the result array
 * Optionally concretize the result and store it
 * Optionally store a permanent constraint on the value if concretized
 *
 * kleeAddressExpr:  the Klee "address" of the memory object
 * sizeInBytes:  the number of bytes to read.  If this is too large
 *               read the maximum amount possible from one MemoryObject
 * result: optional parameter (can be NULL) to store the result
 * requireConcrete: if true, fail if the memory is not concrete
 * concretize: if true, concretize the memory but don't necessarily
 *             add a permanent constraint (i.e. get an example)
 * addConstraint: permanently concretize the memory
 */
void S2EExecutionState::kleeReadMemory(ref<Expr> kleeAddressExpr, uint64_t sizeInBytes, std::vector<ref<Expr>> *result,
                                       bool requireConcrete, bool concretize, bool addConstraint) {
    ObjectPair op;
    kleeAddressExpr = g_s2e->getExecutor()->toUnique(*this, kleeAddressExpr);
    ref<klee::ConstantExpr> address = cast<klee::ConstantExpr>(kleeAddressExpr);

#ifdef CONFIG_SYMBEX_MP
    if (!addressSpace.resolveOne(address, op))
        assert(0 && "kleeReadMemory: out of bounds / multiple resolution unhandled");

    const MemoryObject *mo = op.first;
    const ObjectState *os = op.second;

    assert(requireConcrete || (!requireConcrete && concretize && addConstraint) ||
           (!requireConcrete && concretize && !addConstraint) || (!requireConcrete && !concretize));

    // Read an array of bytes
    unsigned i;
    sizeInBytes = sizeInBytes >= mo->size ? mo->size : sizeInBytes;
    for (i = 0; i < sizeInBytes; i++) {
        ref<Expr> cur = os->read8(i);
        if (requireConcrete) {
            // Here, we demand concrete results
            cur = g_s2e->getExecutor()->toUnique(*this, cur);
            assert(isa<klee::ConstantExpr>(cur) && "kleeReadMemory: hit symbolic char but expected concrete data");
            if (result) {
                result->push_back(cast<klee::ConstantExpr>(cur));
            }
        } else {
            if (concretize && addConstraint) {
                // Add constraint if necessary
                cur = g_s2e->getExecutor()->toConstant(*this, cur, "kleeReadMemory");
            } else if (concretize && !addConstraint) {
                // Otherwise just get an example
                cur = g_s2e->getExecutor()->toConstantSilent(*this, cur);
            } else {
                assert(false && "Expected reasonable parameters in kleeReadMemory");
            }

            if (result) {
                result->push_back(cur);
            }
        }
    }

    if (result) {
        assert(result->size() >= 1 && "Expected array to have results");
    }
#else
    unsigned i;
    uint64_t caddr = address->getZExtValue();
    for (i = 0; i < sizeInBytes; i++) {
        ref<Expr> cur = readMemory8(caddr);
        result->push_back(cur);
        caddr++;
    }
#endif
}

/*
 * Write bytes to a given KLEE address.
 * Assumes that only one memory object is involved and that
 * the write does not span memory objects.
 *
 * kleeAddressExpr:  the Klee "address" of the memory object
 * bytes:  The bytes to write at that location.
 */
void S2EExecutionState::kleeWriteMemory(ref<Expr> kleeAddressExpr, /* Address */
                                        std::vector<ref<Expr>> &bytes) {
    ObjectPair op;
    kleeAddressExpr = g_s2e->getExecutor()->toUnique(*this, kleeAddressExpr);
    ref<klee::ConstantExpr> address = cast<klee::ConstantExpr>(kleeAddressExpr);
#ifdef CONFIG_SYMBEX_MP
    if (!addressSpace.resolveOne(address, op))
        assert(0 && "kleeReadMemory: out of bounds / multiple resolution unhandled");

    const MemoryObject *mo = op.first;
    const ObjectState *os = op.second;
    ObjectState *wos = addressSpace.getWriteable(mo, os);
    assert(bytes.size() <= os->size && "Too many bytes supplied to kleeWriteMemory");

    // Write an array of possibly-symbolic bytes
    unsigned i;
    for (i = 0; i < bytes.size(); i++) {
        wos->write(i, bytes[i]);
    }
#else
    unsigned i;
    uint64_t caddr = address->getZExtValue();
    for (i = 0; i < bytes.size(); i++) {
        writeMemory8(caddr + i, bytes[i]);
    }
#endif
}

void S2EExecutionState::makeSymbolic(std::vector<ref<Expr>> &args, bool makeConcolic) {
    assert(args.size() == 3);

    // KLEE address of variable
    ref<klee::ConstantExpr> kleeAddress = cast<klee::ConstantExpr>(args[0]);

    // Size in bytes
    uint64_t sizeInBytes = cast<klee::ConstantExpr>(args[1])->getZExtValue();

    // address of label and label string itself
    ref<klee::Expr> labelKleeAddress = args[2];
    std::vector<klee::ref<klee::Expr>> result;
    kleeReadMemory(labelKleeAddress, 31, &result, true, false, false);
    char *strBuf = new char[32];
    assert(result.size() <= 31 && "Expected fewer bytes??  See kleeReadMemory");
    unsigned i;
    for (i = 0; i < result.size(); i++) {
        strBuf[i] = cast<klee::ConstantExpr>(result[i])->getZExtValue(8);
    }
    strBuf[i] = 0;
    std::string labelStr(strBuf);
    delete[] strBuf;

    // Now insert the symbolic/concolic data for this state
    std::vector<ref<Expr>> existingData;
    std::vector<uint8_t> concreteData;
    std::vector<ref<Expr>> symb;

    if (makeConcolic) {
        kleeReadMemory(labelKleeAddress, sizeInBytes, &existingData, false, true, true);
        for (unsigned i = 0; i < sizeInBytes; ++i) {
            concreteData.push_back(cast<klee::ConstantExpr>(existingData[i])->getZExtValue(8));
        }
        symb = createConcolicArray(labelStr, sizeInBytes, concreteData);
    } else {
        symb = createSymbolicArray(labelStr, sizeInBytes);
    }

    kleeWriteMemory(kleeAddress, symb);
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
        setSp(getSp() + size);
        setPc(getTb()->pcOfLastInstr);
        jumpToSymbolicCpp();
    }
}

void S2EExecutionState::jumpToSymbolicCpp() {
    if (!isRunningConcrete()) {
        return;
    }
    m_toRunSymbolically.insert(std::make_pair(getPc(), getPageDir()));
    m_startSymbexAtPC = getPc();

    // XXX: how to make this cleaner?
    g_s2e->getExecutor()->updateConcreteFastPath(this);

    // XXX: what about regs_to_env ?
    throw CpuExitException();
}

void S2EExecutionState::jumpToSymbolic() {
    assert(isActive() && isRunningConcrete());

    m_toRunSymbolically.insert(std::make_pair(getPc(), getPageDir()));
    m_startSymbexAtPC = getPc();

    // XXX: how to make this cleaner?
    g_s2e->getExecutor()->updateConcreteFastPath(this);

    // XXX: what about regs_to_env ?
    longjmp(env->jmp_env, 1);
}

bool S2EExecutionState::needToJumpToSymbolic() const {
    return isRunningConcrete();
}

/***/

bool S2EExecutionState::merge(const ExecutionState &_b) {
    assert(dynamic_cast<const S2EExecutionState *>(&_b));
    const S2EExecutionState &b = static_cast<const S2EExecutionState &>(_b);

    assert(!m_active && !b.m_active);

    llvm::raw_ostream &s = g_s2e->getInfoStream(this);

    if (DebugLogStateMerge)
        s << "Attempting merge with state " << b.getID() << '\n';

    if (pc != b.pc) {
        if (DebugLogStateMerge) {
            s << "merge failed: different KLEE pc\n" << *(*pc).inst << "\n" << *(*b.pc).inst << "\n";

            s << "symb regs a: " << hexval(regs()->getSymbolicRegistersMask()) << "\n";
            s << "symb regs b: " << hexval(b.regs()->getSymbolicRegistersMask()) << "\n";

            std::stringstream ss;
            g_s2e->getExecutor()->printStack(*this, NULL, ss);
            g_s2e->getExecutor()->printStack(b, NULL, ss);
            s << ss.str() << "\n";
        }
        return false;
    }

    // XXX is it even possible for these to differ? does it matter? probably
    // implies difference in object states?
    if (symbolics != b.symbolics) {
        if (DebugLogStateMerge) {
            s << "merge failed: different symbolics" << '\n';

            foreach2 (it, symbolics.begin(), symbolics.end()) { s << (*it).first->name << "\n"; }
            s << "\n";
            foreach2 (it, b.symbolics.begin(), b.symbolics.end()) { s << (*it).first->name << "\n"; }
        }
        return false;
    }

    {
        std::vector<StackFrame>::const_iterator itA = stack.begin();
        std::vector<StackFrame>::const_iterator itB = b.stack.begin();
        while (itA != stack.end() && itB != b.stack.end()) {
            // XXX vaargs?
            if (itA->caller != itB->caller || itA->kf != itB->kf) {
                if (DebugLogStateMerge)
                    s << "merge failed: different callstacks" << '\n';
            }
            ++itA;
            ++itB;
        }
        if (itA != stack.end() || itB != b.stack.end()) {
            if (DebugLogStateMerge)
                s << "merge failed: different callstacks" << '\n';
            return false;
        }
    }

    std::set<ref<Expr>> aConstraints = constraints.getConstraintSet();
    std::set<ref<Expr>> bConstraints = b.constraints.getConstraintSet();
    std::set<ref<Expr>> commonConstraints, aSuffix, bSuffix;

    std::set_intersection(aConstraints.begin(), aConstraints.end(), bConstraints.begin(), bConstraints.end(),
                          std::inserter(commonConstraints, commonConstraints.begin()));

    std::set_difference(aConstraints.begin(), aConstraints.end(), commonConstraints.begin(), commonConstraints.end(),
                        std::inserter(aSuffix, aSuffix.end()));

    std::set_difference(bConstraints.begin(), bConstraints.end(), commonConstraints.begin(), commonConstraints.end(),
                        std::inserter(bSuffix, bSuffix.end()));
    if (DebugLogStateMerge) {
        s << "\tconstraint prefix: [";
        for (std::set<ref<Expr>>::iterator it = commonConstraints.begin(), ie = commonConstraints.end(); it != ie; ++it)
            s << *it << ", ";
        s << "]\n";
        s << "\tA suffix: [";
        for (std::set<ref<Expr>>::iterator it = aSuffix.begin(), ie = aSuffix.end(); it != ie; ++it)
            s << *it << ", ";
        s << "]\n";
        s << "\tB suffix: [";
        for (std::set<ref<Expr>>::iterator it = bSuffix.begin(), ie = bSuffix.end(); it != ie; ++it)
            s << *it << ", ";
        s << "]" << '\n';
    }

    /* Check CPUX86State */
    {
        if (m_registers.compareArchitecturalConcreteState(b.m_registers)) {
            if (DebugLogStateMerge)
                s << "merge failed: different concrete cpu state" << '\n';
            return false;
        }
    }

    // We cannot merge if addresses would resolve differently in the
    // states. This means:
    //
    // 1. Any objects created since the branch in either object must
    // have been free'd.
    //
    // 2. We cannot have free'd any pre-existing object in one state
    // and not the other

    // if(DebugLogStateMerge) {
    //    s << "\tchecking object states\n";
    //    s << "A: " << addressSpace.objects << "\n";
    //    s << "B: " << b.addressSpace.objects << "\n";
    //}

    std::set<const MemoryObject *> mutated;
    MemoryMap::iterator ai = addressSpace.objects.begin();
    MemoryMap::iterator bi = b.addressSpace.objects.begin();
    MemoryMap::iterator ae = addressSpace.objects.end();
    MemoryMap::iterator be = b.addressSpace.objects.end();
    for (; ai != ae && bi != be; ++ai, ++bi) {
        if (ai->first != bi->first) {
            if (DebugLogStateMerge) {
                if (ai->first < bi->first) {
                    s << "\t\tB misses binding for: " << ai->first->id << "\n";
                } else {
                    s << "\t\tA misses binding for: " << bi->first->id << "\n";
                }
            }
            if (DebugLogStateMerge)
                s << "merge failed: different callstacks" << '\n';
            return false;
        }
        if (ai->second != bi->second && !ai->first->isValueIgnored &&
            ai->first != S2EExecutionStateRegisters::getConcreteRegs() &&
            ai->first != S2EExecutionStateMemory::getDirtyMask()) {

            const MemoryObject *mo = ai->first;
            if (DebugLogStateMerge)
                s << "\t\tmutated: " << mo->id << " (" << mo->name << ")\n";
            if (mo->isSharedConcrete) {
                if (DebugLogStateMerge)
                    s << "merge failed: different shared-concrete objects " << '\n';
                return false;
            }
            mutated.insert(mo);
        }
    }
    if (ai != ae || bi != be) {
        if (DebugLogStateMerge)
            s << "merge failed: different address maps" << '\n';
        return false;
    }

    // Create state predicates
    ref<Expr> inA = ConstantExpr::alloc(1, Expr::Bool);
    ref<Expr> inB = ConstantExpr::alloc(1, Expr::Bool);

    for (std::set<ref<Expr>>::iterator it = aSuffix.begin(), ie = aSuffix.end(); it != ie; ++it) {
        inA = AndExpr::create(inA, *it);
    }

    for (std::set<ref<Expr>>::iterator it = bSuffix.begin(), ie = bSuffix.end(); it != ie; ++it) {
        inB = AndExpr::create(inB, *it);
    }

    // XXX should we have a preference as to which predicate to use?
    // it seems like it can make a difference, even though logically
    // they must contradict each other and so inA => !inB

    // merge LLVM stacks

    int selectCountStack = 0, selectCountMem = 0;

    std::vector<StackFrame>::iterator itA = stack.begin();
    std::vector<StackFrame>::const_iterator itB = b.stack.begin();
    for (; itA != stack.end(); ++itA, ++itB) {
        StackFrame &af = *itA;
        const StackFrame &bf = *itB;
        for (unsigned i = 0; i < af.kf->numRegisters; i++) {
            ref<Expr> &av = af.locals[i].value;
            const ref<Expr> &bv = bf.locals[i].value;
            if (av.isNull() || bv.isNull()) {
                // if one is null then by implication (we are at same pc)
                // we cannot reuse this local, so just ignore
            } else {
                if (av != bv) {
                    av = SelectExpr::create(inA, av, bv);
                    selectCountStack += 1;
                }
            }
        }
    }

    if (DebugLogStateMerge) {
        s << "\t\tcreated " << selectCountStack << " select expressions on the stack\n";
    }

    for (std::set<const MemoryObject *>::iterator it = mutated.begin(), ie = mutated.end(); it != ie; ++it) {
        const MemoryObject *mo = *it;
        const ObjectState *os = addressSpace.findObject(mo);
        const ObjectState *otherOS = b.addressSpace.findObject(mo);
        assert(os && !os->readOnly && "objects mutated but not writable in merging state");
        assert(otherOS);

        if (DebugLogStateMerge) {
            s << "Merging object " << mo->name << "\n";
        }

        ObjectState *wos = addressSpace.getWriteable(mo, os);
        for (unsigned i = 0; i < mo->size; i++) {
            ref<Expr> av = wos->read8(i);
            ref<Expr> bv = otherOS->read8(i);
            if (av != bv) {
                ref<Expr> e = SelectExpr::create(inA, av, bv);
                wos->write(i, e);
                selectCountMem += 1;
            }
        }
    }

    if (DebugLogStateMerge)
        s << "\t\tcreated " << selectCountMem << " select expressions in memory\n";

    // XXX: Need to roll back the state of the incremental solver to the last
    // common constraint.
    constraints = ConstraintManager();
    for (std::set<ref<Expr>>::iterator it = commonConstraints.begin(), ie = commonConstraints.end(); it != ie; ++it)
        constraints.addConstraint(*it);

    constraints.addConstraint(OrExpr::create(inA, inB));

    this->constraints = constraints;

    // XXX: do we need to recompute concolic values?

    // Merge dirty mask by clearing bits that differ. Clearning bits in
    // dirty mask can only affect performance but not correcntess.
    // NOTE: this requires flushing TLB
    {
        const MemoryObject *dirtyMask = S2EExecutionStateMemory::getDirtyMask();
        const ObjectState *os = addressSpace.findObject(dirtyMask);
        ObjectState *wos = addressSpace.getWriteable(dirtyMask, os);
        uint8_t *dirtyMaskA = wos->getConcreteStore();
        const uint8_t *dirtyMaskB = b.addressSpace.findObject(dirtyMask)->getConcreteStore();

        for (unsigned i = 0; i < dirtyMask->size; ++i) {
            if (dirtyMaskA[i] != dirtyMaskB[i])
                dirtyMaskA[i] = 0;
        }
    }

    return true;
}

void S2EExecutionState::enumPossibleRanges(ref<Expr> e, ref<Expr> start, ref<Expr> end, std::vector<Range> &ranges) {

    Solver *solver = g_s2e->getExecutor()->getSolver(*this);

    std::vector<const Array *> symbObjects;
    foreach2 (it, symbolics.begin(), symbolics.end()) { symbObjects.push_back(it->second); }

    solver->getRanges(constraints, symbObjects, e, start, end, ranges);
}

/***/

void S2EExecutionState::addConstraint(klee::ref<klee::Expr> e) {
#ifdef CONFIG_SYMBEX_MP
    if (DebugConstraints) {
        if (ConcolicMode) {
            klee::ref<klee::Expr> ce = concolics->evaluate(e);
            assert(ce->isTrue() && "Expression must be true here");
        }

        // Check that the added constraint is consistent with
        // the existing path constraints
        bool truth;
        Solver *solver = g_s2e->getExecutor()->getSolver(*this);
        Query query(constraints, e);
        // bool res = solver->mayBeTrue(query, mayBeTrue);
        bool res = solver->mustBeTrue(query.negateExpr(), truth);
        if (!res || truth) {
            g_s2e->getWarningsStream() << "State has invalid constraints" << '\n';
            exit(-1);
            // g_s2e->getExecutor()->terminateStateEarly(*this, "State has invalid constraint set");
        }
        assert(res && !truth && "state has invalid constraint set");
    }

    constraints.addConstraint(e);
#endif
}

/// \brief Try to solve additional state constraints
///
/// Find solution for merged original state constraints and
/// supplied additional constraints.
///
/// \param c additional constraints
/// \param newConstraints merged constraints will be saved here, can be NULL
/// \param newConcolics computed concolic values will be saved here, can be NULL
/// \return true if solution exists
///
bool S2EExecutionState::testConstraints(const std::vector<ref<Expr>> &c, ConstraintManager *newConstraints,
                                        Assignment *newConcolics) {
#ifdef CONFIG_SYMBEX_MP
    ConstraintManager tmpConstraints = constraints;
    foreach2 (it, c.begin(), c.end()) {
        s2e_assert(this, !(isa<ConstantExpr>(*it) && dyn_cast<ConstantExpr>(*it)->isFalse()),
                   "Attempt to add invalid (false) constraint");
        tmpConstraints.addConstraint(*it);
    }

    std::vector<const Array *> symbObjects;
    foreach2 (it, symbolics.begin(), symbolics.end()) { symbObjects.push_back(it->second); }

    Solver *solver = g_s2e->getExecutor()->getSolver(*this);
    std::vector<std::vector<unsigned char>> concreteObjects;
    if (!solver->getInitialValues(Query(tmpConstraints, ConstantExpr::create(0, Expr::Bool)), symbObjects,
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

/// \brief Apply new constraints to the state
///
/// Checks whether new state constraints are consistent.
///
/// \param c additional constraints
/// \return true if constraints were applied
///
bool S2EExecutionState::applyConstraints(const std::vector<ref<Expr>> &c) {
    return testConstraints(c, &constraints, ConcolicMode ? concolics : NULL);
}

/***/

// XXX: This should go out of here
void S2EExecutionState::dumpStack(unsigned count) {
    dumpStack(count, getSp());
}

// XXX: This should go out of here
void S2EExecutionState::dumpStack(unsigned count, uint64_t sp) {
    std::stringstream os;

    os << "Dumping stack @0x" << std::hex << sp << '\n';

    for (unsigned i = 0; i < count; ++i) {
        klee::ref<klee::Expr> val = readMemory(sp + i * sizeof(uint32_t), klee::Expr::Int32);
        klee::ConstantExpr *ce = dyn_cast<klee::ConstantExpr>(val);
        if (ce) {
            os << std::hex << "0x" << sp + i * sizeof(uint32_t) << " 0x" << std::setw(sizeof(uint32_t) * 2)
               << std::setfill('0') << val;
            os << std::setfill(' ');
        } else {
            os << std::hex << "0x" << sp + i * sizeof(uint32_t) << val;
        }
        os << '\n';
    }

    g_s2e->getDebugStream();
}

uint64_t S2EExecutionState::concretize(klee::ref<klee::Expr> expression, const std::string &reason, bool silent) {
#ifdef CONFIG_SYMBEX_MP
    if (silent) {
        return g_s2e->getExecutor()->toConstantSilent(*this, expression)->getZExtValue();
    } else {
        return g_s2e->getExecutor()->toConstant(*this, expression, reason.c_str())->getZExtValue();
    }
#else
    ConstantExpr *ce = dyn_cast<ConstantExpr>(expression);
    assert(ce && "Expression must be constant here");
    return ce->getZExtValue();
#endif
}

void S2EExecutionState::addressSpaceChange(const klee::MemoryObject *mo, const klee::ObjectState *oldState,
                                           klee::ObjectState *newState) {
    if (oldState && mo->isMemoryPage) {
        if ((mo->address & ~SE_RAM_OBJECT_MASK) == 0) {
            m_asCache.invalidate(mo->address & SE_RAM_OBJECT_MASK);
            m_tlb.addressSpaceChangeUpdateTlb(mo, oldState, newState);
#ifdef SE_ENABLE_PHYSRAM_TLB
            m_tlb.updateRamTlb(mo, oldState, newState);
#endif
        }
    } else {
        m_registers.addressSpaceChange(mo, oldState, newState);
    }

    g_s2e->getCorePlugin()->onAddressSpaceChange.emit(this, mo, oldState, newState);
}

void S2EExecutionState::addressSpaceSymbolicStatusChange(ObjectState *object, bool becameConcrete) {
    // Deal with CPU registers
    g_s2e->getExecutor()->updateConcreteFastPath(this);

    // Deal with RAM
    if (object->getBitArraySize() != SE_RAM_OBJECT_SIZE) {
        return;
    }

    object = m_asCache.getBaseObject(object);
    m_tlb.updateTlb(object->getObject(), object, object);
}

void S2EExecutionState::addressSpaceObjectSplit(const ObjectState *oldObject,
                                                const std::vector<ObjectState *> &newObjects) {
    // Splitting can only happen to RAM
    ObjectState *baseObject = m_asCache.notifySplit(oldObject, newObjects);
    m_tlb.updateTlb(oldObject->getObject(), oldObject, baseObject);
}

uint64_t S2EExecutionState::readMemIoVaddr(bool masked) {
    klee::ref<klee::Expr> result;

    if (m_memIoVaddr.isNull()) {
        return env->mem_io_vaddr;
    }

    if (masked) {
        result = AndExpr::create(m_memIoVaddr, klee::ConstantExpr::create(TARGET_PAGE_MASK, m_memIoVaddr->getWidth()));
        if (ConcolicMode) {
            // This assumes that the page is already fully constrained by the MMU
            result = concolics->evaluate(result);
            assert(dyn_cast<ConstantExpr>(result) && "Expression must be constant here");
        } else {
            result = g_s2e->getExecutor()->toConstant(*this, result, "Reading mem_io_vaddr");
        }
    } else {
        result = m_memIoVaddr;
        result = g_s2e->getExecutor()->toConstant(*this, result, "Reading mem_io_vaddr");
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
    if (!TCGLLVMContext::GetStaticBranchTarget(BB, target)) {
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
        if (!TCGLLVMContext::GetStaticBranchTarget(BB, &results[i])) {
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
    TranslationBlock *tb = s2e_read_register_concrete_fast<TranslationBlock *>(CPU_OFFSET(se_current_tb));
    bool is32 = (tb->flags >> HF_CS32_SHIFT) & 1;
    bool is64 = (tb->flags >> HF_CS64_SHIFT) & 1;
    if (is64) {
        return 8;
    } else if (is32) {
        return 4;
    } else {
        return 2;
    }
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

void S2EExecutionState::disassemble(llvm::raw_ostream &os, uint64_t pc, unsigned size) {
    TranslationBlock *tb = s2e_read_register_concrete_fast<TranslationBlock *>(CPU_OFFSET(se_current_tb));
    int flags = 0; // 32-bit code by default

    if (tb) {
        switch (getPointerSize()) {
            case 4:
                flags = 0;
                break;
            case 8:
                flags = 2;
                break;
            default:
                assert(false && "Not supported code");
        }
    }

    FILE *fp = reinterpret_cast<FILE *>(&os);
    target_disas_ex(fp, __disas_print, pc, size, flags);
}

/// \brief Print query to solve constraints
///
/// \param constraints constraints
/// \param symbolics symbolic objects
/// \param os output stream
///
/// Will print query in format understandable by kleaver.
///
void S2EExecutionState::dumpQuery(
    const ConstraintManager &constraints,
    const std::vector<std::pair<const klee::MemoryObject *, const klee::Array *>> &symbolics, llvm::raw_ostream &os) {
    // Extract symbolic objects
    std::vector<const Array *> symbObjects;
    for (unsigned i = 0; i < symbolics.size(); ++i) {
        symbObjects.push_back(symbolics[i].second);
    }

    ExprPPrinter *printer = ExprPPrinter::create(os);

    Query query(constraints, ConstantExpr::alloc(0, Expr::Bool));
    printer->printQuery(os, query.constraints, query.expr, 0, 0, &symbObjects[0], &symbObjects[0] + symbObjects.size());
    os.flush();

    delete printer;
}

/// \brief Print query to solve state constraints
///
/// \param os output stream
///
/// Will print query in format understandable by kleaver.
///
void S2EExecutionState::dumpQuery(llvm::raw_ostream &os) const {
    dumpQuery(constraints, symbolics, os);
}

} // namespace s2e

/******************************************/
/* Functions for the s2e-libcpu interface */

extern "C" {

s2e::S2EExecutionState *g_s2e_state = NULL;

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
    g_s2e_state->regs()->readSymbolicRegion(offset, buf, size, true);
}

void s2e_write_register_concrete(unsigned offset, uint8_t *buf, unsigned size) {
    g_s2e_state->regs()->writeSymbolicRegion(offset, buf, size);
}

uint8_t se_read_dirty_mask(uint64_t host_address) {
    return g_s2e_state->readDirtyMask(host_address);
}

void se_write_dirty_mask(uint64_t host_address, uint8_t val) {
    return g_s2e_state->writeDirtyMask(host_address, val);
}

static inline CPUTLBRAMEntry *s2e_get_ram_tlb_entry(uint64_t host_address) {
#if defined(SE_ENABLE_PHYSRAM_TLB)
    uintptr_t tlb_index = (host_address >> 12) & (CPU_TLB_SIZE - 1);
    CPUX86State *env = g_s2e_state->regs()->getCpuState();
    return &env->se_ram_tlb[tlb_index];
#else
    return NULL;
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
                klee::ObjectState *os = static_cast<klee::ObjectState *>(te->object_state);
                os = g_s2e_state->addressSpace.getWriteable(os->getObject(), os);
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
    g_s2e_state->readMemoryConcrete(hostAddress, buf, size, s2e::HostAddress);
#endif
}

void s2e_dma_write(uint64_t hostAddress, uint8_t *buf, unsigned size) {
#if defined(SE_ENABLE_PHYSRAM_TLB)
    s2e_dma_rw(hostAddress, buf, size, true);
#else
    g_s2e_state->writeMemoryConcrete(hostAddress, buf, size, s2e::HostAddress);
#endif
}

void s2e_read_ram_concrete_check(uint64_t host_address, uint8_t *buf, uint64_t size) {
    assert(g_s2e_state->isRunningConcrete());

    bool exitOnSymbolicRead = g_s2e_state->isSymbolicExecutionEnabled();
    CPUTLBRAMEntry *re = s2e_get_ram_tlb_entry(host_address);
    g_s2e_state->mem()->transferRam(re, host_address, buf, size, false, exitOnSymbolicRead, false);
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

} // extern "C"
