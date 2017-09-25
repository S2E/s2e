///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_EXECUTIONSTATE_H
#define S2E_EXECUTIONSTATE_H

#include <klee/ExecutionState.h>
#include <klee/IConcretizer.h>
#include <klee/Memory.h>

#include "AddressSpaceCache.h"
#include "S2EDeviceState.h"
#include "S2EExecutionStateMemory.h"
#include "S2EExecutionStateRegisters.h"
#include "S2EExecutionStateTlb.h"

#include "S2EStatsTracker.h"
#include "s2e_config.h"

extern "C" {
struct TranslationBlock;
struct TimersState;
}

// XXX
struct CPUX86State;

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/SmallVector.h>
#include <tr1/unordered_map>

namespace s2e {

class Plugin;
class PluginState;
class S2EDeviceState;
class S2EExecutionState;
struct S2ETranslationBlock;

// typedef std::tr1::unordered_map<const Plugin*, PluginState*> PluginStateMap;
typedef std::map<const Plugin *, PluginState *> PluginStateMap;
typedef PluginState *(*PluginStateFactory)(Plugin *p, S2EExecutionState *s);

class S2EExecutionState : public klee::ExecutionState, public klee::IConcretizer {
protected:
    friend class S2EExecutor;

    static unsigned s_lastSymbolicId;

    /** Unique numeric ID for the state */
    int m_stateID;

    PluginStateMap m_PluginState;

    bool m_symbexEnabled;

    /* Internal variable - set to PC where execution should be
       switched to symbolic (e.g., due to access to symbolic memory */
    uint64_t m_startSymbexAtPC;

    /** Set to true when the state is active (i.e., currently selected).
        NOTE: for active states, SharedConcrete memory objects are stored
              in shared locations, for inactive - in ObjectStates. */
    bool m_active;

    /** Set to true when the state is killed. The cpu loop actively checks
        for such a condition, and, when met, asks the scheduler to get a new
        state */
    bool m_zombie;

    /** Set to true if this state is yielding. */
    bool m_yielded;

    /** Set to true when the state executes code in concrete mode.
        NOTE: When m_runningConcrete is true, CPU registers that contain
              concrete values are stored in the shared region (env global
              variable), all other CPU registers are stored in ObjectState.
    */
    bool m_runningConcrete;

    /**
     * The state will stay in the current S2E process.
     * The load balancer will not send it to a different process;
     */
    bool m_pinned;

    /**
     * Do not switch to any other state until this state is killed.
     */
    bool m_isStateSwitchForbidden;

    typedef std::set<std::pair<uint64_t, uint64_t>> ToRunSymbolically;
    ToRunSymbolically m_toRunSymbolically;

    S2EDeviceState m_deviceState;

    AddressSpaceCache m_asCache;

    S2EExecutionStateRegisters m_registers;

    S2EExecutionStateMemory m_memory;

    /* The following structure is used to store libcpu time accounting
       variables while the state is inactive */
    TimersState *m_timersState;

    S2ETranslationBlock *m_lastS2ETb;

    bool m_needFinalizeTBExec;

    bool m_forkAborted;

    unsigned m_nextSymbVarId;

    S2EStateStats m_stats;

    S2EExecutionStateTlb m_tlb;

    /* Temp location to store a symbolic mem_io_vaddr */
    klee::ref<klee::Expr> m_memIoVaddr;

    /** Set when execution enters doInterrupt, reset when it exits. */
    bool m_runningExceptionEmulationCode;

    ExecutionState *clone();
    virtual void addressSpaceChange(const klee::MemoryObject *mo, const klee::ObjectState *oldState,
                                    klee::ObjectState *newState);

    virtual void addressSpaceObjectSplit(const klee::ObjectState *oldObject,
                                         const std::vector<klee::ObjectState *> &newObjects);

    void addressSpaceChangeUpdateRegisters(const klee::MemoryObject *mo, const klee::ObjectState *oldState,
                                           klee::ObjectState *newState);

    std::string getUniqueVarName(const std::string &name, std::string &rawVar);

public:
    virtual void addressSpaceSymbolicStatusChange(klee::ObjectState *object, bool becameConcrete);

public:
    S2EExecutionState(klee::KFunction *kf);
    ~S2EExecutionState();

    int getID() const {
        return m_stateID;
    }

    S2EDeviceState *getDeviceState() {
        return &m_deviceState;
    }

    TranslationBlock *getTb() const;

    /*************************************************/

    PluginState *getPluginState(Plugin *plugin, PluginStateFactory factory) {
        PluginStateMap::iterator it = m_PluginState.find(plugin);
        if (it == m_PluginState.end()) {
            PluginState *ret = factory(plugin, this);
            assert(ret);
            m_PluginState[plugin] = ret;
            return ret;
        }
        return (*it).second;
    }

    /** Returns true if this is the active state */
    inline bool isActive() const {
        return m_active;
    }

    inline bool isZombie() const {
        return m_zombie;
    }
    inline void zombify() {
        m_zombie = true;
    }

    /** Yield the state. */
    bool isYielded() const {
        return m_yielded;
    }
    void yield(bool new_yield_state) {
        m_yielded = new_yield_state;
    }

    bool isPinned() const {
        return m_pinned;
    }

    void setPinned(bool p) {
        m_pinned = p;
    }

    inline bool isStateSwitchForbidden() const {
        return m_isStateSwitchForbidden;
    }
    inline void setStateSwitchForbidden(bool v) {
        m_isStateSwitchForbidden = v;
    }

    /** Returns true if this state is currently running in concrete mode */
    inline bool isRunningConcrete() const {
        return m_runningConcrete;
    }

    // XXX: Move to S2EExecutionStateMemory.cpp
    uint64_t readMemIoVaddr(bool masked);
    void writeMemIoVaddr(klee::ref<klee::Expr> value) {
        m_memIoVaddr = value;
    }

    /** Handler for tcg_llvm_make_symbolic, tcg_llvm_get_value. */
    void makeSymbolic(std::vector<klee::ref<klee::Expr>> &args, bool makeConcolic);
    void kleeReadMemory(klee::ref<klee::Expr> kleeAddressExpr, uint64_t sizeInBytes,
                        std::vector<klee::ref<klee::Expr>> *result, bool concreteOnly = false, bool concretize = false,
                        bool addConstraint = false);
    void kleeWriteMemory(klee::ref<klee::Expr> kleeAddressExpr, std::vector<klee::ref<klee::Expr>> &bytes);

    bool getReturnAddress(uint64_t *retAddr);
    bool bypassFunction(unsigned paramCount);

    void jumpToSymbolic() __attribute__((noreturn));
    void jumpToSymbolicCpp();
    bool needToJumpToSymbolic() const;
    void undoCallAndJumpToSymbolic();

    void dumpStack(unsigned count);
    void dumpStack(unsigned count, uint64_t sp);

    bool isForkingEnabled() const {
        return !forkDisabled;
    }
    void setForking(bool enable) {
        forkDisabled = !enable;
    }

    void enableForking();
    void disableForking();

    bool isSymbolicExecutionEnabled() const {
        return m_symbexEnabled;
    }

    bool isRunningExceptionEmulationCode() const {
        return m_runningExceptionEmulationCode;
    }

    inline void setRunningExceptionEmulationCode(bool val) {
        m_runningExceptionEmulationCode = val;
    }

    void enableSymbolicExecution();
    void disableSymbolicExecution();

    /** Read value from memory, returning false if the value is symbolic */
    bool readMemoryConcrete(uint64_t address, void *buf, uint64_t size, AddressType addressType = VirtualAddress) {
        return m_memory.readMemoryConcrete(address, buf, size, addressType);
    }

    /** Write concrete value to memory */
    bool writeMemoryConcrete(uint64_t address, void *buf, uint64_t size, AddressType addressType = VirtualAddress) {
        return m_memory.writeMemoryConcrete(address, buf, size, addressType);
    }

    /** Virtual address translation (debug mode). Returns -1 on failure. */
    uint64_t getPhysicalAddress(uint64_t virtualAddress) const {
        return m_memory.getPhysicalAddress(virtualAddress);
    }

    /** Address translation (debug mode). Returns host address or -1 on failure */
    uint64_t getHostAddress(uint64_t address, AddressType addressType = VirtualAddress) const {
        return m_memory.getHostAddress(address, addressType);
    }

    /** Access to state's memory. Address is virtual or physical,
        depending on 'physical' argument. Returns NULL or false in
        case of failure (can't resolve virtual address or physical
        address is invalid) */
    klee::ref<klee::Expr> readMemory(uint64_t address, klee::Expr::Width width,
                                     AddressType addressType = VirtualAddress) {
        return m_memory.readMemory(address, width, addressType);
    }

    klee::ref<klee::Expr> readMemory8(uint64_t address, AddressType addressType = VirtualAddress) {
        return m_memory.readMemory8(address, addressType);
    }

    bool readMemoryConcrete8(uint64_t address, uint8_t *result = NULL, AddressType addressType = VirtualAddress,
                             bool addConstraint = true) {
        return m_memory.readMemoryConcrete8(address, result, addressType, addConstraint);
    }

    bool writeMemory(uint64_t address, klee::ref<klee::Expr> value, AddressType addressType = VirtualAddress) {
        return m_memory.writeMemory(address, value, addressType);
    }

    bool writeMemory(uint64_t address, uint8_t *buf, klee::Expr::Width width,
                     AddressType addressType = VirtualAddress) {
        return m_memory.writeMemoryConcrete(address, buf, width / 8, addressType);
    }

    bool writeMemory8(uint64_t address, klee::ref<klee::Expr> value, AddressType addressType = VirtualAddress) {
        return m_memory.writeMemory8(address, value, addressType);
    }

    // XXX: this should be templatized
    bool writeMemory8(uint64_t address, uint8_t value, AddressType addressType = VirtualAddress) {
        return m_memory.writeMemory(address, value, addressType);
    }

    bool writeMemory16(uint64_t address, uint16_t value, AddressType addressType = VirtualAddress) {
        return m_memory.writeMemory(address, value, addressType);
    }

    bool writeMemory32(uint64_t address, uint32_t value, AddressType addressType = VirtualAddress) {
        return m_memory.writeMemory(address, value, addressType);
    }

    bool writeMemory64(uint64_t address, uint64_t value, AddressType addressType = VirtualAddress) {
        return m_memory.writeMemory(address, value, addressType);
    }

    /** Dirty mask management */
    uint8_t readDirtyMask(uint64_t hostAddress) {
        return m_memory.readDirtyMask(hostAddress);
    }

    void writeDirtyMask(uint64_t hostAddress, uint8_t value) {
        m_memory.writeDirtyMask(hostAddress, value);
    }

    void registerDirtyMask(uint64_t hostAddress, uint64_t size) {
        m_memory.registerDirtyMask(hostAddress, size);
    }

    virtual void addConstraint(klee::ref<klee::Expr> e);
    bool testConstraints(const std::vector<klee::ref<klee::Expr>> &c, klee::ConstraintManager *newConstraints = NULL,
                         klee::Assignment *newConcolics = NULL);
    bool applyConstraints(const std::vector<klee::ref<klee::Expr>> &c);

    /** Creates new unconstrained symbolic value */
    klee::ref<klee::Expr> createSymbolicValue(const std::string &name = std::string(),
                                              klee::Expr::Width width = klee::Expr::Int32);

    std::vector<klee::ref<klee::Expr>> createSymbolicArray(const std::string &name = std::string(), unsigned size = 4,
                                                           std::string *varName = NULL);

    /** Create a symbolic value tied to an example concrete value */
    /** If the concrete buffer is empty, creates a purely symbolic value */
    klee::ref<klee::Expr> createConcolicValue(const std::string &name, klee::Expr::Width width,
                                              const std::vector<unsigned char> &buffer);

    template <typename T> klee::ref<klee::Expr> createConcolicValue(const std::string &name, T val) {
        std::vector<uint8_t> concolicValue(sizeof(T));
        union {
            // XXX: assumes little endianness!
            T value;
            uint8_t concolicArray[sizeof(T)];
        };

        value = val;

        for (unsigned i = 0; i < sizeof(T); ++i) {
            concolicValue[i] = concolicArray[i];
        }
        return createConcolicValue(name, sizeof(T) * 8, concolicValue);
    }

    std::vector<klee::ref<klee::Expr>> createConcolicArray(const std::string &name, unsigned size,
                                                           const std::vector<unsigned char> &concreteBuffer,
                                                           std::string *varName = NULL);

    /** Attempt to merge two states */
    bool merge(const ExecutionState &b);

    S2EExecutionStateTlb *getTlb() {
        return &m_tlb;
    }

    /*********************************************************/

    virtual uint64_t concretize(klee::ref<klee::Expr> expression, const std::string &reason, bool silent);

    S2EExecutionStateRegisters *regs() {
        return &m_registers;
    }

    const S2EExecutionStateRegisters *regs() const {
        return &m_registers;
    }

    S2EExecutionStateMemory *mem() {
        return &m_memory;
    }

    // XXX: Rename that
    CPUX86State *getConcreteCpuState() const {
        return m_registers.getNativeCpuState();
    }

    /** Returns a mask of registers that contains symbolic values */
    uint64_t getSymbolicRegistersMask() const {
        return m_registers.getSymbolicRegistersMask();
    }

    /** Read CPU general purpose register */
    klee::ref<klee::Expr> readCpuRegister(unsigned offset, klee::Expr::Width width) const {
        return m_registers.readSymbolicRegion(offset, width);
    }

    /** Write CPU general purpose register */
    void writeCpuRegister(unsigned offset, klee::ref<klee::Expr> value) {
        m_registers.writeSymbolicRegion(offset, value);
    }

    /** Same as writeCpuRegister but also allows writing symbolic values */
    void writeCpuRegisterSymbolic(unsigned offset, klee::ref<klee::Expr> value) {
        m_registers.writeSymbolicRegionUnsafe(offset, value);
    }

    /** Read concrete value from general purpose CPU register */
    bool readCpuRegisterConcrete(unsigned offset, void *buf, unsigned size) {
        return m_registers.readSymbolicRegion(offset, buf, size);
    }

    /** Write concrete value to general purpose CPU register */
    void writeCpuRegisterConcrete(unsigned offset, const void *buf, unsigned size) {
        m_registers.writeSymbolicRegion(offset, buf, size);
    }

    template <typename T> bool readPointer(uint64_t address, T &value) {
        bool status = false;
        if (getPointerSize() == 4) {
            uint32_t pointer = 0;
            status = mem()->readMemoryConcrete(address, &pointer, sizeof(pointer));
            value = pointer;
        } else {
            if (sizeof(T) == 8) {
                uint64_t pointer = 0;
                status = mem()->readMemoryConcrete(address, &pointer, sizeof(pointer));
                value = pointer;
            }
        }
        return status;
    }

    bool writePointer(uint64_t address, uint64_t value) {
        if (getPointerSize() == 4) {
            if (value <= 0xffffffff) {
                return mem()->writeMemory(address, (uint32_t) value);
            }
        } else {
            return mem()->writeMemory(address, value);
        }
        return false;
    }

    uint64_t getPc() const {
        return m_registers.getPc();
    }

    uint64_t getPageDir() const {
        return m_registers.getPageDir();
    }

    uint64_t getSp() const {
        return m_registers.getSp();
    }

    uint64_t getFlags() {
        return m_registers.getFlags();
    }

    void setPc(uint64_t pc) {
        m_registers.setPc(pc);
    }

    void setSp(uint64_t sp) {
        return m_registers.setSp(sp);
    }

    unsigned getPointerSize() const;
    klee::Expr::Width getPointerWidth() const {
        return getPointerSize() * CHAR_BIT;
    }

    void disassemble(llvm::raw_ostream &os, uint64_t pc, unsigned size);

    bool getStaticBranchTargets(uint64_t *truePc, uint64_t *falsePc);
    bool getStaticTarget(uint64_t *target);

    void enumPossibleRanges(klee::ref<klee::Expr> e, klee::ref<klee::Expr> start, klee::ref<klee::Expr> end,
                            std::vector<klee::Range> &ranges);

    static void dumpQuery(const klee::ConstraintManager &constraints,
                          const std::vector<std::pair<const klee::MemoryObject *, const klee::Array *>> &symbolics,
                          llvm::raw_ostream &os);
    void dumpQuery(llvm::raw_ostream &os) const;
};
}

extern "C" {
extern s2e::S2EExecutionState *g_s2e_state;
}

#endif // S2E_EXECUTIONSTATE_H
