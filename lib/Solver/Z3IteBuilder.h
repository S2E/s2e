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

#ifndef KLEE_LIB_SOLVER_Z3ITEBUILDER_H_
#define KLEE_LIB_SOLVER_Z3ITEBUILDER_H_

#include <map>

#include "Z3Builder.h"

namespace klee {

class Z3IteBuilderCache : public Z3BuilderCache {
public:
    typedef std::vector<z3::expr> ExprVector;
    typedef std::pair<const ArrayPtr &, const UpdateNode *> Update;
    typedef std::pair<Z3_ast, Update> ReadUpdatePair;

    virtual bool findArray(const ArrayPtr &root, boost::shared_ptr<ExprVector> &ev) = 0;
    virtual void insertArray(const ArrayPtr &root, boost::shared_ptr<ExprVector> ev) = 0;

    virtual bool findRead(const ReadUpdatePair &rup, z3::expr &expr) = 0;
    virtual void insertRead(const ReadUpdatePair &rup, const z3::expr &expr) = 0;
};

class Z3IteBuilderCacheNoninc : public Z3IteBuilderCache {
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

    virtual bool findArray(const ArrayPtr &root, boost::shared_ptr<ExprVector> &ev) {
        ArrayVariableMap::iterator it = array_variables_.find(root);
        if (it != array_variables_.end()) {
            ev = it->second;
            return true;
        }
        return false;
    }

    virtual void insertArray(const ArrayPtr &root, boost::shared_ptr<ExprVector> ev) {
        array_variables_.insert(std::make_pair(root, ev));
    }

    virtual bool findRead(const ReadUpdatePair &rup, z3::expr &expr) {
        ReadMap::iterator it = read_map_.find(rup);
        if (it != read_map_.end()) {
            expr = it->second;
            return true;
        }
        return false;
    }

    virtual void insertRead(const ReadUpdatePair &rup, const z3::expr &expr) {
        read_map_.insert(std::make_pair(rup, expr));
    }

protected:
    virtual void push() { /*nop*/
    }
    virtual void pop(unsigned n) {
        reset();
    }

    virtual void reset() {
        cons_expr_.clear();
        array_variables_.clear();
        read_map_.clear();
    }

private:
    typedef ExprHashMap<z3::expr> ExprMap;

    typedef std::unordered_map<ArrayPtr, boost::shared_ptr<ExprVector>, ArrayHash> ArrayVariableMap;
    typedef std::map<ReadUpdatePair, z3::expr> ReadMap;

    ExprMap cons_expr_;
    ArrayVariableMap array_variables_;
    ReadMap read_map_;
};

class Z3IteBuilder : public Z3Builder {
public:
    Z3IteBuilder(z3::context &context, Z3IteBuilderCache *cache);
    virtual ~Z3IteBuilder();

    virtual z3::expr getInitialRead(const ArrayPtr &root, unsigned index);

protected:
    virtual z3::expr makeReadExpr(ref<ReadExpr> re);

private:
    typedef std::vector<z3::expr> ExprVector;

    z3::expr getReadForArray(z3::expr index, const ArrayPtr &root, const UpdateNode *un);
    z3::expr getReadForInitialArray(z3::expr index, const ArrayPtr &root);

    boost::shared_ptr<ExprVector> getArrayValues(const ArrayPtr &root);

    Z3IteBuilderCache *cache_;
};

} /* namespace klee */

#endif /* KLEE_LIB_SOLVER_Z3ITEBUILDER_H_ */
