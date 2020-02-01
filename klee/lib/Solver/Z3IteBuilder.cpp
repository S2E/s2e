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

#include "Z3IteBuilder.h"

#include <boost/make_shared.hpp>

using boost::make_shared;
using boost::shared_ptr;

namespace klee {

/* Z3IteBuilder --------------------------------------------------------------*/

Z3IteBuilder::Z3IteBuilder(z3::context &context, Z3IteBuilderCache *cache) : Z3Builder(context, cache), cache_(cache) {
}

Z3IteBuilder::~Z3IteBuilder() {
}

z3::expr Z3IteBuilder::getInitialRead(const ArrayPtr &root, unsigned index) {
    shared_ptr<ExprVector> elem_vector = getArrayValues(root);
    return (*elem_vector)[index];
}

z3::expr Z3IteBuilder::makeReadExpr(ref<ReadExpr> re) {
    return getReadForArray(getOrMakeExpr(re->getIndex()), re->getUpdates()->getRoot(),
                           re->getUpdates()->getHead().get());
}

z3::expr Z3IteBuilder::getReadForArray(z3::expr index, const ArrayPtr &root, const UpdateNode *un) {
    Z3IteBuilderCache::ReadUpdatePair rup = std::make_pair(index, std::make_pair(root, un));
    z3::expr result(context_);
    if (cache_->findRead(rup, result)) {
        return result;
    }

    if (!un) {
        result = getReadForInitialArray(index, root);
    } else {
        result = z3::to_expr(context_,
                             Z3_mk_ite(context_, index == getOrMakeExpr(un->getIndex()), getOrMakeExpr(un->getValue()),
                                       getReadForArray(index, root, un->getNext().get())));
    }
    cache_->insertRead(rup, result);
    return result;
}

z3::expr Z3IteBuilder::getReadForInitialArray(z3::expr index, const ArrayPtr &root) {
    shared_ptr<ExprVector> elem_vector = getArrayValues(root);

    // TODO: balance this tree
    z3::expr ite_tree = context_.bv_val(0, 8);
    for (unsigned i = 0, e = root->getSize(); i != e; ++i) {
        ite_tree =
            z3::to_expr(context_, Z3_mk_ite(context_, index == context_.bv_val(i, 32), (*elem_vector)[i], ite_tree));
    }
    return ite_tree;
}

shared_ptr<Z3IteBuilder::ExprVector> Z3IteBuilder::getArrayValues(const ArrayPtr &root) {
    shared_ptr<Z3IteBuilder::ExprVector> elem_vector;
    if (cache_->findArray(root, elem_vector)) {
        return elem_vector;
    }

    elem_vector = make_shared<ExprVector>();

    if (root->isConstantArray()) {
        for (unsigned i = 0, e = root->getSize(); i != e; ++i) {
            elem_vector->push_back(context_.bv_val((unsigned) root->getConstantValues()[i]->getZExtValue(), 8));
        }
    } else {
        char buf[256];
        for (unsigned i = 0, e = root->getSize(); i != e; ++i) {
            snprintf(buf, sizeof(buf), "%s_%p_%u", root->getName().c_str(), (void *) root.get(), i);
            elem_vector->push_back(context_.bv_const(buf, 8));
        }
    }

    cache_->insertArray(root, elem_vector);
    return elem_vector;
}

} /* namespace klee */
