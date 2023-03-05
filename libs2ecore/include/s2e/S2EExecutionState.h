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
#include "S2ETranslationBlock.h"
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

typedef std::unordered_map<const Plugin *, PluginState *> PluginStateMap;
typedef PluginState *(*PluginStateFactory)(Plugin *p, S2EExecutionState *s);

class S2EExecutionState : public klee::ExecutionState, public klee::IConcretizer {
protected:
    friend class S2EExecutor;

    static unsigned s_lastSymbolicId;

    ///
    /// \brief State identifier
    ///
    /// This identifier is guaranteed to be unique on each instance of S2E.
    /// It may not be unique across instances, as load balancing may
    /// choose to keep one state in both the child and the parent instance.
    ///
    int m_stateID;

    ///
    /// \brief Globally unique state identifier
    ///
    /// This uniquely identifes a state across all S2E instances.
    ///
    unsigned m_guid;

    PluginStateMap m_PluginState;

    /* Internal variable - set to PC where execution should be
       switched to symbolic (e.g., due to access to symbolic memory). */
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

    S2ETranslationBlockPtr m_lastS2ETb;

    bool m_needFinalizeTBExec;

    bool m_forkAborted;

    unsigned m_nextSymbVarId;

    S2EExecutionStateTlb m_tlb;

    /* Temp location to store a symbolic mem_io_vaddr */
    klee::ref<klee::Expr> m_memIoVaddr;

    /** Set when execution enters doInterrupt, reset when it exits. */
    bool m_runningExceptionEmulationCode;

    virtual void addressSpaceChange(const klee::ObjectKey &key, const klee::ObjectStateConstPtr &oldState,
                                    const klee::ObjectStatePtr &newState);

    virtual void addressSpaceObjectSplit(const klee::ObjectStateConstPtr &oldObject,
                                         const std::vector<klee::ObjectStatePtr> &newObjects);

    void addressSpaceChangeUpdateRegisters(const klee::ObjectStateConstPtr &oldState,
                                           const klee::ObjectStatePtr &newState);

    std::string getUniqueVarName(const std::string &name, std::string &rawVar);

public:
    virtual void addressSpaceSymbolicStatusChange(const klee::ObjectStatePtr &object, bool becameConcrete);

public:
    S2EExecutionState(klee::KFunction *kf);
    ~S2EExecutionState();

    virtual ExecutionState *clone();

    int getID() const {
        return m_stateID;
    }

    int getGuid() const {
        return m_guid;
    }

    void setMemIoVaddr(const klee::ref<klee::Expr> &e) {
        m_memIoVaddr = e;
    }

    ///
    /// \brief Assign a new state id.
    ///
    /// This must only be done by the S2EExecutor when load-balancing
    /// states.
    ///
    void assignGuid(uint64_t guid);

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

    template <typename T> T *getPluginState(Plugin *plugin) const {
        auto it = m_PluginState.find(plugin);
        if (it == m_PluginState.end()) {
            return nullptr;
        }
        return dynamic_cast<T *>((*it).second);
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

    void setYieldState(bool new_yield_state) {
        m_yielded = new_yield_state;
    }

    ///
    /// \brief Yields the state and raises an exception to exit the cpu loop
    ///
    /// This forces a call to the searcher in order to select the next state.
    /// The next state may or may not be the same as the one that yielded.
    /// It is up to the caller to define a searcher policy
    /// (e.g., enforce that another state is scheduled).
    /// yield() only provides a mechanism.
    ///
    void yield();

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

    bool getReturnAddress(uint64_t *retAddr);
    bool bypassFunction(unsigned paramCount);

    void jumpToSymbolic() __attribute__((noreturn));
    void jumpToSymbolicCpp();
    bool needToJumpToSymbolic() const;
    void undoCallAndJumpToSymbolic();

    /** Copy concrete values to their proper location, concretizing
        if necessary (most importantly it will concretize CPU registers.
        Note: this is required only to execute generated code,
        other libcpu components access all registers through wrappers. */
    void switchToConcrete();

    /** Copy concrete values to the execution state storage */
    void switchToSymbolic();

    bool isForkingEnabled() const {
        return !forkDisabled;
    }
    void setForking(bool enable) {
        forkDisabled = !enable;
    }

    void enableForking();
    void disableForking();

    bool isRunningExceptionEmulationCode() const {
        return m_runningExceptionEmulationCode;
    }

    inline void setRunningExceptionEmulationCode(bool val) {
        m_runningExceptionEmulationCode = val;
    }

    bool testConstraints(const std::vector<klee::ref<klee::Expr>> &c, klee::ConstraintManager *newConstraints = nullptr,
                         klee::Assignment *newConcolics = nullptr);

    /** Creates new unconstrained symbolic value */
    klee::ref<klee::Expr> createSymbolicValue(const std::string &name = std::string(),
                                              klee::Expr::Width width = klee::Expr::Int32);

    std::vector<klee::ref<klee::Expr>> createSymbolicArray(const std::string &name = std::string(), unsigned size = 4,
                                                           std::string *varName = nullptr);

    /** Create a symbolic value tied to an example concrete value */
    /** If the concrete buffer is empty, creates a purely symbolic value */
    klee::ref<klee::Expr> createSymbolicValue(const std::string &name, klee::Expr::Width width,
                                              const std::vector<unsigned char> &buffer);

    template <typename T> klee::ref<klee::Expr> createSymbolicValue(const std::string &name, T val) {
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
        return createSymbolicValue(name, sizeof(T) * 8, concolicValue);
    }

    std::vector<klee::ref<klee::Expr>> createSymbolicArray(const std::string &name, unsigned size,
                                                           const std::vector<unsigned char> &concreteBuffer,
                                                           std::string *varName = nullptr);

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

    template <typename T> bool readPointer(uint64_t address, T &value) {
        bool status = false;
        if (getPointerSize() == 4) {
            uint32_t pointer = 0;
            status = mem()->read(address, &pointer, sizeof(pointer));
            value = pointer;
        } else {
            if (sizeof(T) == 8) {
                uint64_t pointer = 0;
                status = mem()->read(address, &pointer, sizeof(pointer));
                value = pointer;
            }
        }
        return status;
    }

    bool writePointer(uint64_t address, uint64_t value) {
        if (getPointerSize() == 4) {
            if (value <= 0xffffffff) {
                return mem()->write(address, (uint32_t) value);
            }
        } else {
            return mem()->write(address, value);
        }
        return false;
    }

    ///////////////////////////////////////////////////////

    unsigned getPointerSize() const;
    klee::Expr::Width getPointerWidth() const {
        return getPointerSize() * CHAR_BIT;
    }

    bool disassemble(llvm::raw_ostream &os, uint64_t pc, unsigned size);
    bool disassemble(llvm::raw_ostream &os, uint64_t pc, unsigned size, unsigned pointerSize);

    bool getStaticBranchTargets(uint64_t *truePc, uint64_t *falsePc);
    bool getStaticTarget(uint64_t *target);

    void enumPossibleRanges(klee::ref<klee::Expr> e, klee::ref<klee::Expr> start, klee::ref<klee::Expr> end,
                            std::vector<klee::Range> &ranges);
};
} // namespace s2e

extern "C" {
extern s2e::S2EExecutionState *g_s2e_state;
}

#endif // S2E_EXECUTIONSTATE_H
