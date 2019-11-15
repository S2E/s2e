/*
 * S2E Selective Symbolic Execution Platform
 *
 * Copyright (c) 2015, Dependable Systems Laboratory, EPFL
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

#ifndef KLEE_LIB_SOLVER_Z3ARRAYBUILDER_H_
#define KLEE_LIB_SOLVER_Z3ARRAYBUILDER_H_

#include "Z3Builder.h"

namespace klee {

class Z3ArrayBuilderCache : public Z3BuilderCache {
public:
    virtual bool findArray(const ArrayPtr &root, z3::expr &expr) = 0;
    virtual void insertArray(const ArrayPtr &root, const z3::expr &expr) = 0;

    virtual bool findUpdate(const UpdateNode *un, z3::expr &expr) = 0;
    virtual void insertUpdate(const UpdateNode *un, const z3::expr &expr) = 0;
};

class Z3ArrayBuilderCacheNoninc : public Z3ArrayBuilderCache {
public:
    virtual bool findExpr(ref<Expr> e, z3::expr &expr) {
        ExprMap::iterator it = cons_expr_.find(e);
        if (it != cons_expr_.end()) {
            expr = it->second;
            return true;
        }
        return false;
    }

    virtual void insertExpr(ref<Expr> e, const z3::expr &expr) {
        cons_expr_.insert(std::make_pair(e, expr));
    }

    virtual bool findArray(const ArrayPtr &root, z3::expr &expr) {
        ArrayMap::iterator it = cons_arrays_.find(root);
        if (it != cons_arrays_.end()) {
            expr = it->second;
            return true;
        }
        return false;
    }

    virtual void insertArray(const ArrayPtr &root, const z3::expr &expr) {
        cons_arrays_.insert(std::make_pair(root, expr));
    }

    virtual bool findUpdate(const UpdateNode *un, z3::expr &expr) {
        UpdateListMap::iterator it = cons_updates_.find(un);
        if (it != cons_updates_.end()) {
            expr = it->second;
            return true;
        }
        return false;
    }

    virtual void insertUpdate(const UpdateNode *un, const z3::expr &expr) {
        cons_updates_.insert(std::make_pair(un, expr));
    }

protected:
    virtual void push() { /*nop*/
    }
    virtual void pop(unsigned n) {
        reset();
    }

    virtual void reset() {
        cons_expr_.clear();
        cons_arrays_.clear();
        cons_updates_.clear();
    }

private:
    typedef ExprHashMap<z3::expr> ExprMap;
    typedef std::unordered_map<ArrayPtr, z3::expr, ArrayHash> ArrayMap;
    typedef llvm::DenseMap<const UpdateNode *, z3::expr> UpdateListMap;

    ExprMap cons_expr_;
    ArrayMap cons_arrays_;
    UpdateListMap cons_updates_;
};

class Z3ArrayBuilderCacheInc : public Z3ArrayBuilderCache {
public:
    Z3ArrayBuilderCacheInc() : Z3ArrayBuilderCache() {
        stack_.push_back(Frame(expr_map_factory_.getEmptyMap(), array_map_factory_.getEmptyMap(),
                               update_map_factory_.getEmptyMap()));
    }

    virtual bool findExpr(ref<Expr> e, z3::expr &expr) {
        assert(stack_.size() > 0);
        ExprMap &cons_expr = stack_.back().cons_expr_;

        const z3::expr *result = cons_expr.lookup(e);
        if (!result)
            return false;
        expr = *result;
        return true;
    }

    virtual void insertExpr(ref<Expr> e, const z3::expr &expr) {
        assert(stack_.size() > 0);
        ExprMap &cons_expr = stack_.back().cons_expr_;
        cons_expr = expr_map_factory_.add(cons_expr, e, expr);
    }

    virtual bool findArray(const ArrayPtr &root, z3::expr &expr) {
        assert(stack_.size() > 0);
        ArrayMap &cons_arrays = stack_.back().cons_arrays_;

        const z3::expr *result = cons_arrays.lookup(root);
        if (!result)
            return false;
        expr = *result;
        return true;
    }

    virtual void insertArray(const ArrayPtr &root, const z3::expr &expr) {
        assert(stack_.size() > 0);
        ArrayMap &cons_arrays = stack_.back().cons_arrays_;
        cons_arrays = array_map_factory_.add(cons_arrays, root, expr);
    }

    virtual bool findUpdate(const UpdateNode *un, z3::expr &expr) {
        assert(stack_.size() > 0);
        UpdateListMap &cons_updates = stack_.back().cons_updates_;

        const z3::expr *result = cons_updates.lookup(un);
        if (!result)
            return false;
        expr = *result;
        return true;
    }

    virtual void insertUpdate(const UpdateNode *un, const z3::expr &expr) {
        assert(stack_.size() > 0);
        UpdateListMap &cons_updates = stack_.back().cons_updates_;
        cons_updates = update_map_factory_.add(cons_updates, un, expr);
    }

protected:
    virtual void push() {
        stack_.push_back(stack_.back());
    }

    virtual void pop(unsigned n) {
        assert(stack_.size() > n);
        while (n-- > 0) {
            stack_.pop_back();
        }
    }

    virtual void reset() {
        stack_.clear();
        stack_.push_back(Frame(expr_map_factory_.getEmptyMap(), array_map_factory_.getEmptyMap(),
                               update_map_factory_.getEmptyMap()));
    }

private:
    typedef llvm::ImmutableMap<ref<Expr>, z3::expr> ExprMap;
    typedef llvm::ImmutableMap<ArrayPtr, z3::expr> ArrayMap;
    typedef llvm::ImmutableMap<const UpdateNode *, z3::expr> UpdateListMap;

    struct Frame {
        Frame(const ExprMap &initial_expr, const ArrayMap &initial_arrays, const UpdateListMap &initial_updates)
            : cons_expr_(initial_expr), cons_arrays_(initial_arrays), cons_updates_(initial_updates) {
        }

        ExprMap cons_expr_;
        ArrayMap cons_arrays_;
        UpdateListMap cons_updates_;
    };

    ExprMap::Factory expr_map_factory_;
    ArrayMap::Factory array_map_factory_;
    UpdateListMap::Factory update_map_factory_;
    std::vector<Frame> stack_;
};

class Z3ArrayBuilder : public Z3Builder {
public:
    Z3ArrayBuilder(z3::context &context, Z3ArrayBuilderCache *cache);
    virtual ~Z3ArrayBuilder();

    virtual z3::expr getInitialRead(const ArrayPtr &root, unsigned index);

protected:
    virtual z3::expr makeReadExpr(ref<ReadExpr> re);
    virtual z3::expr initializeArray(const ArrayPtr &root, z3::expr array_ast) = 0;

private:
    z3::expr getArrayForUpdate(const ArrayPtr &root, const UpdateNode *un);
    z3::expr getInitialArray(const ArrayPtr &root);

    Z3ArrayBuilderCache *cache_;
};

class Z3StoreArrayBuilder : public Z3ArrayBuilder {
public:
    Z3StoreArrayBuilder(z3::context &context, Z3ArrayBuilderCache *cache);
    virtual ~Z3StoreArrayBuilder();

protected:
    virtual z3::expr initializeArray(const ArrayPtr &root, z3::expr array_ast);
};

class Z3AssertArrayBuilder : public Z3ArrayBuilder {
public:
    Z3AssertArrayBuilder(z3::solver &solver, Z3ArrayBuilderCache *cache);
    virtual ~Z3AssertArrayBuilder();

protected:
    virtual z3::expr initializeArray(const ArrayPtr &root, z3::expr array_ast);

private:
    z3::expr getArrayAssertion(const ArrayPtr &root, z3::expr array_ast);

    z3::solver solver_;
};

} /* namespace klee */

#endif /* KLEE_LIB_SOLVER_Z3ARRAYBUILDER_H_ */
