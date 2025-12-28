//===-- ExecutionState.h ----------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_EXECUTIONSTATE_H
#define KLEE_EXECUTIONSTATE_H

#include "klee/Constraints.h"
#include "klee/Expr.h"

#include "klee/AddressSpace.h"
#include "klee/Internal/Module/Cell.h"
#include "klee/Internal/Module/KInstIterator.h"
#include "klee/Internal/Module/KModule.h"

#include "klee/BitfieldSimplifier.h"
#include "klee/Solver.h"
#include "klee/util/Assignment.h"
#include "IAddressSpaceNotification.h"

#include "IExecutionState.h"
#include "LLVMExecutionState.h"

#include <map>
#include <set>
#include <vector>

namespace klee {
class Array;
struct Cell;
struct KInstruction;

llvm::raw_ostream &operator<<(llvm::raw_ostream &os, const MemoryMap &mm);

class ExecutionState : public IExecutionState, public IAddressSpaceNotification {
public:
    /// Set of objects that should not be merged by the base merge function.
    /// Overloaded functions will take care of it.
    static std::set<ObjectKey, ObjectKeyLTS> s_ignoredMergeObjects;

private:
    SolverPtr m_solver;
    AddressSpace m_addressSpace;

    /// Simplifier user to simplify expressions when adding them
    static BitfieldSimplifier s_simplifier;

    ConstraintManager m_constraints;

    ExecutionState() : m_addressSpace(this), llvm(this) {
    }

protected:
    /// ordered list of symbolics: used to generate test cases.
    std::vector<ArrayPtr> m_symbolics;
    AssignmentPtr m_concolics;

    virtual void addressSpaceChange(const klee::ObjectKey &key, const ObjectStateConstPtr &oldState,
                                    const ObjectStatePtr &newState);

    virtual void addressSpaceObjectSplit(const ObjectStateConstPtr &oldObject,
                                         const std::vector<ObjectStatePtr> &newObjects);

    ExecutionState(const ExecutionState &state) : m_addressSpace(state.m_addressSpace), llvm(state.llvm) {
        m_solver = state.m_solver;
        m_addressSpace.setState(this);
        m_constraints = state.m_constraints;
        m_symbolics = state.m_symbolics;
        m_concolics = Assignment::create(true);
        forkDisabled = state.forkDisabled;
        llvm.state = this;
    }

public:
    /// Disables forking, set by user code.
    bool forkDisabled;
    LLVMExecutionState llvm;

    virtual SolverPtr solver() {
        return m_solver;
    }

    virtual AddressSpace &addressSpace() {
        return m_addressSpace;
    }

    virtual const AddressSpace &addressSpace() const {
        return m_addressSpace;
    }

    virtual const std::vector<ArrayPtr> &symbolics() const {
        return m_symbolics;
    }

    virtual const AssignmentPtr concolics() const {
        return m_concolics;
    }

    virtual void setConcolics(AssignmentPtr concolics) {
        m_concolics = concolics;
    }

    // Fired whenever an object becomes all concrete or gets at least one symbolic byte.
    // Only fired in the context of a memory operation (load/store)
    virtual void addressSpaceSymbolicStatusChange(const ObjectStatePtr &object, bool becameConcrete);

    ExecutionState(KFunction *kf);

    virtual ~ExecutionState();

    virtual ExecutionState *clone();

    const ConstraintManager &constraints() const {
        return m_constraints;
    }

    ///
    /// \brief Add a constraints to the state
    ///
    /// Note: it is very important for the caller to check the return
    /// value of this function. An error while adding a constraint
    /// can lead to incorrect execution.
    ///
    /// \param e the constraint to add
    /// \param recomputeConcolics whether to compute a new set of input values if the new
    /// constraint is valid but does not evaluate to true with the current set of concolic values
    /// \return true if the constraint was successfully added, false otherwise
    ///
    virtual bool addConstraint(const ref<Expr> &e, bool recomputeConcolics = false) __attribute__((warn_unused_result));

    ///
    /// \brief Compute a set of concrete inputs for the given constraints
    /// \param mgr the constraints
    /// \param assignment the concrete inputs
    /// \return true if computation was successful, false if there is no solution
    /// or some other error occured.
    ///
    bool solve(const ConstraintManager &mgr, Assignment &assignment);

    virtual bool merge(const ExecutionState &b);

    bool getSymbolicSolution(std::vector<std::pair<std::string, std::vector<unsigned char>>> &res);

    ref<Expr> simplifyExpr(const ref<Expr> &e) const;

    static BitfieldSimplifier &getSimplifier() {
        return s_simplifier;
    }

    ref<ConstantExpr> toConstant(ref<Expr> e, const std::string &reason);
    uint64_t toConstant(const ref<Expr> &value, const ObjectStateConstPtr &os, size_t offset);
    ref<ConstantExpr> toConstantSilent(ref<Expr> e);

    /// Return a unique constant value for the given expression in the
    /// given state, if it has one (i.e. it provably only has a single
    /// value). Otherwise return the original expression.
    ref<Expr> toUnique(ref<Expr> &e);

    void dumpQuery(llvm::raw_ostream &os) const;

    SolverPtr solver() const;

    // Given a concrete object in our [klee's] address space, add it to
    // objects checked code can reference.
    ObjectStatePtr addExternalObject(void *addr, unsigned size, bool isReadOnly, bool isSharedConcrete = false);

    void bindObject(const ObjectStatePtr &os, bool isLocal);

    void setSolver(SolverPtr &solver) {
        m_solver = solver;
    }

    /// Allocate and bind a new object in a particular state. NOTE: This
    /// function may fork.
    ///
    /// \param isLocal Flag to indicate if the object should be
    /// automatically deallocated on function return (this also makes it
    /// illegal to free directly).
    ///
    /// \param target Value at which to bind the base address of the new
    /// object.
    ///
    /// \param reallocFrom If non-zero and the allocation succeeds,
    /// initialize the new object from the given one and unbind it when
    /// done (realloc semantics). The initialized bytes will be the
    /// minimum of the size of the old and new objects, with remaining
    /// bytes initialized as specified by zeroMemory.
    void executeAlloc(ref<Expr> size, bool isLocal, KInstruction *target, bool zeroMemory = false,
                      const ObjectStatePtr &reallocFrom = nullptr);

    ref<Expr> executeMemoryRead(uint64_t concreteAddress, unsigned bytes);
    void executeMemoryWrite(uint64_t concreteAddress, const ref<Expr> &value);
};
} // namespace klee

#endif
