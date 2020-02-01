/*
 * S2E Selective Symbolic Execution Platform
 *
 * Copyright (c) 2014, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "klee/Common.h"
#include "klee/Constraints.h"
#include "klee/Solver.h"
#include "klee/SolverImpl.h"
#include "klee/SolverStats.h"
#include "klee/util/Assignment.h"
#include "klee/util/ExprHashMap.h"
#include "klee/util/ExprUtil.h"

#include <llvm/Support/CommandLine.h>
#include <llvm/Support/raw_ostream.h>

#include "Z3ArrayBuilder.h"
#include "Z3Builder.h"
#include "Z3IteBuilder.h"

#include <boost/scoped_ptr.hpp>

#include <z3++.h>

#include <iostream>
#include <list>

using namespace llvm;
using boost::scoped_ptr;

namespace {
enum Z3ArrayConsMode { Z3_ARRAY_ITE, Z3_ARRAY_STORES, Z3_ARRAY_ASSERTS };

cl::opt<Z3ArrayConsMode>
    ArrayConsMode("z3-array-cons-mode", cl::desc("Array construction mode in Z3"),
                  cl::values(clEnumValN(Z3_ARRAY_ITE, "ite", "If-then-else expressions over BV variables"),
                             clEnumValN(Z3_ARRAY_STORES, "stores", "Nested store expressions"),
                             clEnumValN(Z3_ARRAY_ASSERTS, "asserts", "Assertions over array values")),
                  cl::init(Z3_ARRAY_ASSERTS));

cl::opt<unsigned> AssumptionResetThreshold("z3-assum-reset-thrs",
                                           cl::desc("Reset threshold for the number of Z3 assumptions"), cl::init(50));

cl::opt<bool> DebugSolverStack("z3-debug-solver-stack", cl::desc("Print debug messages when solver stack is modified"),
                               cl::init(false));
} // namespace

namespace klee {

class Z3BaseSolverImpl : public SolverImpl {
public:
    Z3BaseSolverImpl();
    virtual ~Z3BaseSolverImpl();

    bool computeTruth(const Query &, bool &isValid);
    bool computeValue(const Query &, ref<Expr> &result);
    bool computeInitialValues(const Query &query, const ArrayVec &objects,
                              std::vector<std::vector<unsigned char>> &values, bool &hasSolution);

    void initializeSolver();

protected:
    virtual void createBuilderCache() = 0;

    virtual z3::check_result check(const Query &) = 0;
    virtual void postCheck(const Query &) = 0;

    void extractModel(const ArrayVec &objects, std::vector<std::vector<unsigned char>> &values);

    void push() {
        solver_.push();
        builder_->push();
    }

    void pop(unsigned n = 1) {
        solver_.pop(n);
        builder_->pop(n);
    }

    void reset() {
        solver_.reset();
        builder_->reset();
    }

    z3::context context_;
    z3::solver solver_;

    scoped_ptr<Z3BuilderCache> builder_cache_;
    scoped_ptr<Z3Builder> builder_;

private:
    void configureSolver();
    void createBuilder();
};

class Z3StackSolverImpl : public Z3BaseSolverImpl {
public:
    Z3StackSolverImpl();
    virtual ~Z3StackSolverImpl();

protected:
    typedef std::list<ConditionNodeRef> ConditionNodeList;

    virtual void createBuilderCache();

    virtual z3::check_result check(const Query &);
    virtual void postCheck(const Query &);

    scoped_ptr<ConditionNodeList> last_constraints_;
};

class Z3ResetSolverImpl : public Z3BaseSolverImpl {
public:
    Z3ResetSolverImpl();
    virtual ~Z3ResetSolverImpl();

protected:
    virtual void createBuilderCache();
    virtual z3::check_result check(const Query &);
    virtual void postCheck(const Query &);
};

class Z3AssumptionSolverImpl : public Z3BaseSolverImpl {
public:
    Z3AssumptionSolverImpl();
    virtual ~Z3AssumptionSolverImpl();

protected:
    virtual void createBuilderCache();
    virtual z3::check_result check(const Query &);
    virtual void postCheck(const Query &);

private:
    typedef ExprHashMap<z3::expr> GuardMap;

    z3::expr getAssumption(ref<Expr> assertion);

    GuardMap guards_;
    uint64_t guard_counter_;
};

// Z3Solver ////////////////////////////////////////////////////////////////////

Z3Solver *Z3Solver::createResetSolver() {
    Z3BaseSolverImpl *impl = new Z3ResetSolverImpl();
    impl->initializeSolver();

    return new Z3Solver(impl);
}

Z3Solver *Z3Solver::createStackSolver() {
    Z3BaseSolverImpl *impl = new Z3StackSolverImpl();
    impl->initializeSolver();

    return new Z3Solver(impl);
}

Z3Solver *Z3Solver::createAssumptionSolver() {
    Z3BaseSolverImpl *impl = new Z3AssumptionSolverImpl();
    impl->initializeSolver();

    return new Z3Solver(impl);
}

Z3Solver::Z3Solver(SolverImpl *impl) : Solver(impl) {
}

// Z3BaseSolverImpl ////////////////////////////////////////////////////////////

Z3BaseSolverImpl::Z3BaseSolverImpl() : solver_(context_, "QF_ABV") {
}

Z3BaseSolverImpl::~Z3BaseSolverImpl() {
}

void Z3BaseSolverImpl::extractModel(const ArrayVec &objects, std::vector<std::vector<unsigned char>> &values) {
    z3::model model = solver_.get_model();

    values.reserve(objects.size());
    for (auto &array : objects) {
        std::vector<unsigned char> data;

        data.reserve(array->getSize());
        for (unsigned offset = 0; offset < array->getSize(); ++offset) {
            z3::expr value_ast = model.eval(builder_->getInitialRead(array, offset), true);
            unsigned value_num;

            Z3_bool conv_result = Z3_get_numeral_uint(context_, value_ast, &value_num);
            ::check(conv_result == Z3_TRUE, "Could not convert value");
            assert(value_num < (1 << 8 * sizeof(unsigned char)) && "Invalid model value");

            data.push_back((unsigned char) value_num);
        }
        values.push_back(data);
    }
}

bool Z3BaseSolverImpl::computeTruth(const Query &query, bool &isValid) {
    ArrayVec objects;
    std::vector<std::vector<unsigned char>> values;
    bool hasSolution;

    if (!computeInitialValues(query, objects, values, hasSolution))
        return false;

    isValid = !hasSolution;
    return true;
}

// TODO: Use model evaluation in Z3
bool Z3BaseSolverImpl::computeValue(const Query &query, ref<Expr> &result) {
    ArrayVec objects;
    std::vector<std::vector<unsigned char>> values;
    bool hasSolution;

    findSymbolicObjects(query.expr, objects);
    if (!computeInitialValues(query.withFalse(), objects, values, hasSolution))
        return false;
    assert(hasSolution && "state has invalid constraint set");

    Assignment a(objects, values);
    result = a.evaluate(query.expr);

    return true;
}

bool Z3BaseSolverImpl::computeInitialValues(const Query &query, const ArrayVec &objects,
                                            std::vector<std::vector<unsigned char>> &values, bool &hasSolution) {
    ++stats::queries;
    ++stats::queryCounterexamples;

    z3::check_result result = check(query);

    switch (result) {
        case z3::unknown:
            postCheck(query);
            return false;
        case z3::unsat:
            postCheck(query);
            hasSolution = false;
            ++stats::queriesValid;
            return true;
        case z3::sat:
            extractModel(objects, values);
            postCheck(query);
            hasSolution = true;
            ++stats::queriesInvalid;
            return true;
    }
}

void Z3BaseSolverImpl::configureSolver() {
    (*klee_message_stream) << "[Z3] Initializing\n";

    Z3_param_descrs solver_params = Z3_solver_get_param_descrs(context_, solver_);
    Z3_param_descrs_inc_ref(context_, solver_params);

    z3::params params(context_);
    params.set("array.extensional", false);
    Z3_params_validate(context_, params, solver_params);

    solver_.set(params);

    Z3_param_descrs_dec_ref(context_, solver_params);
}

void Z3BaseSolverImpl::createBuilder() {
    assert(builder_cache_ && "The cache needs to be created first");

    switch (ArrayConsMode) {
        case Z3_ARRAY_ITE:
            builder_.reset(new Z3IteBuilder(context_, (Z3IteBuilderCache *) builder_cache_.get()));
            break;
        case Z3_ARRAY_STORES:
            builder_.reset(new Z3StoreArrayBuilder(context_, (Z3ArrayBuilderCache *) builder_cache_.get()));
            break;
        case Z3_ARRAY_ASSERTS:
            builder_.reset(new Z3AssertArrayBuilder(solver_, (Z3ArrayBuilderCache *) builder_cache_.get()));
            break;
    }
}

void Z3BaseSolverImpl::initializeSolver() {
    configureSolver();
    createBuilderCache();
    createBuilder();
}

// Z3StackSolverImpl ///////////////////////////////////////////////////////////

Z3StackSolverImpl::Z3StackSolverImpl() : Z3BaseSolverImpl(), last_constraints_(new ConditionNodeList()) {
}

Z3StackSolverImpl::~Z3StackSolverImpl() {
}

z3::check_result Z3StackSolverImpl::check(const Query &query) {
    if (DebugSolverStack) {
        *klee_message_stream << "[Z3] query size " << query.constraints.size() << '\n';
    }

    ConditionNodeList *cur_constraints = new ConditionNodeList();

    for (ConditionNodeRef node = query.constraints.head(), root = query.constraints.root(); node != root;
         node = node->parent()) {
        // TODO: Handle special case of fast-forward
        cur_constraints->push_front(node);
    }

    ConditionNodeList::iterator cur_it, last_it;
    cur_it = cur_constraints->begin();
    last_it = last_constraints_->begin();

    while (cur_it != cur_constraints->end() && last_it != last_constraints_->end() && *cur_it == *last_it) {
        cur_it++;
        last_it++;
    }

    if (last_it != last_constraints_->end()) {
        unsigned amount = 1 + last_constraints_->back()->depth() - (*last_it)->depth();

        if (DebugSolverStack) {
            *klee_message_stream << "[Z3] pop " << amount << '\n';
        }

        pop(amount);
    }

    if (cur_it != cur_constraints->end()) {
        if (DebugSolverStack) {
            *klee_message_stream << "[Z3] push " << (cur_constraints->back()->depth() - (*cur_it)->depth() + 1) << '\n';
        }

        while (cur_it != cur_constraints->end()) {
            push();
            solver_.add(builder_->construct((*cur_it)->expr()));
            cur_it++;
        }
    }

    last_constraints_.reset(cur_constraints);

    push();

    // Note the negation, since we're checking for validity
    // (i.e., a counterexample)
    solver_.add(!builder_->construct(query.expr));

    return solver_.check();
}

void Z3StackSolverImpl::postCheck(const Query &) {
    pop();
}

void Z3StackSolverImpl::createBuilderCache() {
    switch (ArrayConsMode) {
        case Z3_ARRAY_ITE:
            builder_cache_.reset(new Z3IteBuilderCacheNoninc());
            break;
        case Z3_ARRAY_STORES:
            builder_cache_.reset(new Z3ArrayBuilderCacheInc());
            break;
        case Z3_ARRAY_ASSERTS:
            builder_cache_.reset(new Z3ArrayBuilderCacheInc());
            break;
    }
}

// Z3ResetSolverImpl ///////////////////////////////////////////////////////////

Z3ResetSolverImpl::Z3ResetSolverImpl() : Z3BaseSolverImpl() {
}

Z3ResetSolverImpl::~Z3ResetSolverImpl() {
}

z3::check_result Z3ResetSolverImpl::check(const Query &query) {
    std::list<ConditionNodeRef> cur_constraints;

    for (ConditionNodeRef node = query.constraints.head(), root = query.constraints.root(); node != root;
         node = node->parent()) {
        cur_constraints.push_front(node);
    }

    for (std::list<ConditionNodeRef>::iterator it = cur_constraints.begin(), ie = cur_constraints.end(); it != ie;
         ++it) {
        solver_.add(builder_->construct((*it)->expr()));
    }

    solver_.add(!builder_->construct(query.expr));
    return solver_.check();
}

void Z3ResetSolverImpl::postCheck(const Query &) {
    reset();
}

void Z3ResetSolverImpl::createBuilderCache() {
    switch (ArrayConsMode) {
        case Z3_ARRAY_ITE:
            builder_cache_.reset(new Z3IteBuilderCacheNoninc());
            break;
        case Z3_ARRAY_STORES:
            builder_cache_.reset(new Z3ArrayBuilderCacheNoninc());
            break;
        case Z3_ARRAY_ASSERTS:
            builder_cache_.reset(new Z3ArrayBuilderCacheNoninc());
            break;
    }
}

// Z3AssumptionSolverImpl //////////////////////////////////////////////////////

Z3AssumptionSolverImpl::Z3AssumptionSolverImpl() : Z3BaseSolverImpl(), guard_counter_(0) {
}

Z3AssumptionSolverImpl::~Z3AssumptionSolverImpl() {
}

z3::check_result Z3AssumptionSolverImpl::check(const Query &query) {
    std::list<ConditionNodeRef> cur_constraints;
    for (ConditionNodeRef node = query.constraints.head(), root = query.constraints.root(); node != root;
         node = node->parent()) {
        cur_constraints.push_front(node);
    }

    z3::expr_vector assumptions(context_);

    for (std::list<ConditionNodeRef>::iterator it = cur_constraints.begin(), ie = cur_constraints.end(); it != ie;
         ++it) {
        assumptions.push_back(getAssumption((*it)->expr()));
    }
    assumptions.push_back(getAssumption(Expr::createIsZero(query.expr)));
    return solver_.check(assumptions);
}

void Z3AssumptionSolverImpl::postCheck(const Query &) {
    if (DebugSolverStack) {
        *klee_message_stream << "[Z3] assumptions " << guards_.size() << '\n';
    }

    if (guards_.size() > AssumptionResetThreshold) {
        reset();
        guards_.clear();
    }
}

z3::expr Z3AssumptionSolverImpl::getAssumption(ref<Expr> assertion) {
    GuardMap::iterator it = guards_.find(assertion);
    if (it != guards_.end()) {
        return it->second;
    }

    char name[16];
    snprintf(name, 16, "g%lu", guard_counter_++);
    z3::expr result = context_.bool_const(name);
    guards_.insert(std::make_pair(assertion, result));

    solver_.add(z3::to_expr(context_, Z3_mk_implies(context_, result, builder_->construct(assertion))));

    return result;
}

void Z3AssumptionSolverImpl::createBuilderCache() {
    switch (ArrayConsMode) {
        case Z3_ARRAY_ITE:
            builder_cache_.reset(new Z3IteBuilderCacheNoninc());
            break;
        case Z3_ARRAY_STORES:
            builder_cache_.reset(new Z3ArrayBuilderCacheNoninc());
            break;
        case Z3_ARRAY_ASSERTS:
            builder_cache_.reset(new Z3ArrayBuilderCacheNoninc());
            break;
    }
}
} // namespace klee
