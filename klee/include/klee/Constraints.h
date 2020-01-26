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

#ifndef KLEE_CONSTRAINTS_H
#define KLEE_CONSTRAINTS_H

#include <algorithm>
#include <exception>
#include <llvm/ADT/SmallVector.h>
#include <llvm/Support/raw_ostream.h>
#include <map>
#include <vector>
#include "klee/Expr.h"
#include "klee/Internal/ADT/ImmutableMap.h"
#include "klee/Solver.h"

// We don't use KLEE's own ref<T> because it is intrusive.
#include <boost/bind.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/weak_ptr.hpp>

namespace klee {

using boost::enable_shared_from_this;
using boost::shared_ptr;
using boost::weak_ptr;

class ConditionNode;
typedef shared_ptr<ConditionNode> ConditionNodeRef;

class ConditionNode : public enable_shared_from_this<ConditionNode> {
public:
    const ConditionNodeRef parent() const {
        return parent_;
    }
    const ref<Expr> expr() const {
        return expr_;
    }
    size_t depth() const {
        return depth_;
    }

protected:
    // Use weak_ptr here to enable automatic deallocation of nodes when they're
    // no longer referenced from a ConstraintManager.
    typedef std::map<ref<Expr>, weak_ptr<ConditionNode>> AdjancencyMap;

    ConditionNode() : depth_(0) {
    }
    ConditionNode(const ConditionNodeRef parent, const ref<Expr> expr)
        : parent_(parent), expr_(expr), depth_(parent->depth_ + 1) {
    }

    ConditionNodeRef getOrCreate(const ref<Expr> expr) {
        if (children_[expr].expired()) {
            ConditionNodeRef new_node = ConditionNodeRef(new ConditionNode(shared_from_this(), expr));
            children_[expr] = weak_ptr<ConditionNode>(new_node);
            return new_node;
        } else {
            return ConditionNodeRef(children_[expr]);
        }
    }

private:
    AdjancencyMap children_;
    const ConditionNodeRef parent_;
    const ref<Expr> expr_;
    size_t depth_;

    friend class ConstraintManager;

    // TODO: At some point in the future, add support for multiple solver
    // sessions, one attached to each branch in this condition tree.
};

class ConditionIterator {
public:
    ConditionIterator(const ConditionNodeRef node) : node_(node) {
    }

    void operator++() {
        node_ = node_->parent();
    }

    void operator++(int) {
        node_ = node_->parent();
    }

    bool operator==(ConditionIterator other) const {
        return node_ == other.node_;
    }

    bool operator!=(ConditionIterator other) const {
        return node_ != other.node_;
    }

    const ref<Expr> operator*() const {
        return node_->expr();
    }

private:
    ConditionNodeRef node_;
};

class ConstraintManager {
public:
    typedef ConditionIterator const_iterator;

    ConstraintManager() {
        root_ = ConditionNodeRef(new ConditionNode());
        head_ = root_;
    }

    ConstraintManager(const ConstraintManager &other) {
        root_ = other.root_;
        head_ = other.head_;
    }

    ConstraintManager &operator=(const ConstraintManager &other) {
        root_ = other.root_;
        head_ = other.head_;
        return *this;
    }

    bool operator==(const ConstraintManager &other) const {
        return head_ == other.head_;
    }

    void addConstraint(const ref<Expr> e);

    const_iterator begin() const {
        return const_iterator(head_);
    }
    const_iterator end() const {
        return const_iterator(root_);
    }

    const ConditionNodeRef head() const {
        return head_;
    }

    const ConditionNodeRef root() const {
        return root_;
    }

    ////////////////////////////////////////////////////////////////////////////
    // BACKWARDS COMPATIBILITY - Must remove at some point

    ConstraintManager(const std::vector<ref<Expr>> &cs) {
        root_ = ConditionNodeRef(new ConditionNode());
        head_ = root_;

        std::for_each(cs.begin(), cs.end(), boost::bind(&ConstraintManager::addConstraint, this, _1));
    }

    ref<Expr> toExpr(const ref<Expr> e) const {
        return e;
    }

    ref<Expr> simplifyExpr(const ref<Expr> e) const {
        return e;
    }

    bool empty() const {
        return head_ == root_;
    }

    size_t size() const {
        return head_->depth();
    }

    std::set<ref<Expr>> getConstraintSet() const {
        std::set<ref<Expr>> result;
        result.insert(begin(), end());
        return result;
    }

    uint64_t getId() const {
        throw std::exception();
    }

private:
    ConditionNodeRef head_;
    ConditionNodeRef root_;
};
} // namespace klee

#endif /* KLEE_CONSTRAINTS_H */
