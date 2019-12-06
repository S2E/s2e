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

#include "Z3ArrayBuilder.h"

namespace klee {

/* Z3ArrayBuilder ------------------------------------------------------------*/

Z3ArrayBuilder::Z3ArrayBuilder(z3::context &context, Z3ArrayBuilderCache *cache)
    : Z3Builder(context, cache), cache_(cache) {
}

Z3ArrayBuilder::~Z3ArrayBuilder() {
}

z3::expr Z3ArrayBuilder::getInitialRead(const ArrayPtr &root, unsigned index) {
    return z3::select(getInitialArray(root), context_.bv_val(index, 32));
}

z3::expr Z3ArrayBuilder::makeReadExpr(ref<ReadExpr> re) {
    return z3::select(getArrayForUpdate(re->getUpdates()->getRoot(), re->getUpdates()->getHead().get()),
                      getOrMakeExpr(re->getIndex()));
}

z3::expr Z3ArrayBuilder::getArrayForUpdate(const ArrayPtr &root, const UpdateNode *un) {
    if (!un) {
        return getInitialArray(root);
    }

    z3::expr result(context_);
    if (cache_->findUpdate(un, result)) {
        return result;
    }

    // TODO: Make non-recursive
    result = z3::store(getArrayForUpdate(root, un->getNext().get()), getOrMakeExpr(un->getIndex()),
                       getOrMakeExpr(un->getValue()));
    cache_->insertUpdate(un, result);
    return result;
}

z3::expr Z3ArrayBuilder::getInitialArray(const ArrayPtr &root) {
    z3::expr result(context_);
    if (cache_->findArray(root, result))
        return result;

    char buf[256];
    snprintf(buf, sizeof(buf), "%s_%p", root->getName().c_str(), (void *) root.get());

    result = context_.constant(buf, context_.array_sort(context_.bv_sort(32), context_.bv_sort(8)));
    if (root->isConstantArray()) {
        result = initializeArray(root, result);
    }
    cache_->insertArray(root, result);
    return result;
}

/* Z3StoreArrayBuilder -------------------------------------------------------*/

Z3StoreArrayBuilder::Z3StoreArrayBuilder(z3::context &context, Z3ArrayBuilderCache *cache)
    : Z3ArrayBuilder(context, cache) {
}

Z3StoreArrayBuilder::~Z3StoreArrayBuilder() {
}

z3::expr Z3StoreArrayBuilder::initializeArray(const ArrayPtr &root, z3::expr array_ast) {
    z3::expr result = array_ast;
    for (unsigned i = 0, e = root->getSize(); i != e; ++i) {
        z3::expr index = context_.bv_val(i, 32);
        z3::expr value = context_.bv_val((unsigned) root->getConstantValues()[i]->getZExtValue(), 8);
        result = z3::store(result, index, value);
    }
    return result;
}

/* Z3AssertArrayBuilder ------------------------------------------------------*/

Z3AssertArrayBuilder::Z3AssertArrayBuilder(z3::solver &solver, Z3ArrayBuilderCache *cache)
    : Z3ArrayBuilder(solver.ctx(), cache), solver_(solver) {
}

Z3AssertArrayBuilder::~Z3AssertArrayBuilder() {
}

z3::expr Z3AssertArrayBuilder::initializeArray(const ArrayPtr &root, z3::expr array_ast) {
    solver_.add(getArrayAssertion(root, array_ast));
    return array_ast;
}

z3::expr Z3AssertArrayBuilder::getArrayAssertion(const ArrayPtr &root, z3::expr array_ast) {
    z3::expr result = context_.bool_val(true);
    for (unsigned i = 0, e = root->getSize(); i != e; ++i) {
        z3::expr array_read = z3::select(array_ast, context_.bv_val(i, 32));
        z3::expr array_value = context_.bv_val((unsigned) root->getConstantValues()[i]->getZExtValue(), 8);

        result = result && (array_read == array_value);
    }
    return result;
}

} /* namespace klee */
