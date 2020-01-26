/*
 * S2E Selective Symbolic Execution Platform
 *
 * Copyright (c) 2016, Cyberhaven
 * Copyright (c) 2012, Dependable Systems Laboratory, EPFL
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
 *
 * Based on Cloud9's ShadowRewrite.cpp, Copyright 2012 Google Inc. All Rights Reserved.
 */

#include <klee/util/Assignment.h>
#include <stack>

namespace klee {

ref<Expr> CachedAssignmentEvaluator::visit(const ref<Expr> &expr) {
    if (isa<ConstantExpr>(expr))
        return expr;

    Assignment::ExpressionCache::iterator it = m_assignment.expressionCache.find(expr);
    if (it != m_assignment.expressionCache.end()) {
        ++m_assignment.cacheHits;
        return it->second;
    }

    ++m_assignment.cacheMisses;
    ref<Expr> result = evaluateActual(expr);

    // We are only interested in constants
    if (isa<ConstantExpr>(result)) {
        m_assignment.expressionCache.insert(std::make_pair(expr, result));
    }

    return result;
}

ref<Expr> CachedAssignmentEvaluator::evaluateActual(const ref<Expr> &expr) {
    if (isa<ReadExpr>(expr))
        return evaluateRead(cast<ReadExpr>(expr));

    if (isa<SelectExpr>(expr))
        return evaluateSelect(cast<SelectExpr>(expr));

    if (isa<AndExpr>(expr))
        return evaluateAnd(cast<AndExpr>(expr));

    if (isa<UDivExpr>(expr) || isa<SDivExpr>(expr) || isa<URemExpr>(expr) || isa<SRemExpr>(expr))
        return evaluateUSDivRem(expr);

    ref<Expr> kids[4];
    for (unsigned i = 0; i < expr->getNumKids(); i++) {
        ref<Expr> kid = expr->getKid(i);
        kids[i] = visit(kid);
    }

    return expr->rebuild(kids);
}

ref<Expr> CachedAssignmentEvaluator::evaluateSelect(const ref<SelectExpr> &expr) {
    ref<Expr> cond = visit(expr->getCondition());
    if (!isa<ConstantExpr>(cond)) {
        return SelectExpr::create(cond, visit(expr->getTrue()), visit(expr->getFalse()));
    }

    ref<ConstantExpr> ce = dyn_cast<ConstantExpr>(cond);
    if (ce->isTrue()) {
        return visit(expr->getTrue());
    } else {
        return visit(expr->getFalse());
    }
}

ref<Expr> CachedAssignmentEvaluator::evaluateUSDivRem(const ref<Expr> &expr) {
    ref<Expr> a1 = visit(expr->getKid(0));
    ref<Expr> a2 = visit(expr->getKid(1));

    ref<Expr> kids[2];
    kids[0] = a1;
    kids[1] = a2;

    ConstantExpr *ce = dyn_cast<ConstantExpr>(a2);
    if (ce && ce->isZero()) {
        // Can't divide by zero, rebuild with the original expression
        kids[1] = expr->getKid(1);
    }

    return expr->rebuild(kids);
}

ref<Expr> CachedAssignmentEvaluator::evaluateAnd(const ref<AndExpr> &expr) {
    ref<Expr> a1 = visit(expr->getKid(0));
    ref<Expr> a2 = visit(expr->getKid(1));

    ConstantExpr *ce = dyn_cast<ConstantExpr>(a1);
    if (ce && ce->isZero()) {
        return a1;
    }

    ce = dyn_cast<ConstantExpr>(a2);
    if (ce && ce->isZero()) {
        return a2;
    }

    return AndExpr::create(a1, a2);
}

ref<Expr> CachedAssignmentEvaluator::evaluateRead(const ref<ReadExpr> &expr) {
    ref<Expr> index = visit(expr->getIndex());
    ConstantExpr *const_index = dyn_cast<ConstantExpr>(index);

    if (!const_index)
        return ReadExpr::create(expr->getUpdates(), index);

    //    assert(const_index->getZExtValue() < expr->getUpdates().getRoot()->size);

    // UpdateList ul = UseRewriteSnapshots ?
    //            RewriteUpdates(expr->getUpdates()) : rewriteUpdatesUncached(expr->getUpdates());
    auto ul = rewriteUpdatesUncached(expr->getUpdates());

    for (auto un = ul->getHead(); un; un = un->getNext()) {
        ConstantExpr *update_index = dyn_cast<ConstantExpr>(un->getIndex());
        if (update_index) {
            if (const_index->getZExtValue() == update_index->getZExtValue())
                return un->getValue();
        } else {
            return ReadExpr::create(UpdateList::create(ul->getRoot(), un), index);
        }
    }

    if (ul->getRoot()->isConstantArray() && const_index->getZExtValue() < ul->getRoot()->getSize()) {
        return ul->getRoot()->getConstantValues()[const_index->getZExtValue()];
    }

    return m_assignment.evaluate(ul->getRoot(), const_index->getZExtValue());

    // return ReadExpr::create(UpdateList(ul.getRoot(), 0), index);
}

UpdateListPtr CachedAssignmentEvaluator::rewriteUpdatesUncached(const UpdateListPtr &ul) {
    auto rewritten = UpdateList::create(ul->getRoot(), 0);

    auto map_it = m_assignment.updateListCache.find(ul->getRoot());

    if (map_it != m_assignment.updateListCache.end()) {
        rewritten = map_it->second;
    }

    std::stack<UpdateNodePtr> update_nodes;

    for (auto un = ul->getHead(); un; un = un->getNext()) {
        update_nodes.push(un);
    }

    // Now apply back all updates
    while (!update_nodes.empty()) {
        auto un = update_nodes.top();
        update_nodes.pop();

        ref<Expr> index = visit(un->getIndex());
        ref<Expr> value = visit(un->getValue());

        rewritten->extend(index, value);
    }

    return rewritten;
}
} // namespace klee
