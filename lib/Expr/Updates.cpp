//===-- Updates.cpp -------------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Expr.h"

#include <cassert>

using namespace klee;

///

UpdateNode::UpdateNode(const UpdateNodePtr &_next, const ref<Expr> &_index, const ref<Expr> &_value)
    : m_refCount(0), next(_next), index(_index), value(_value) {
    assert(_value->getWidth() == Expr::Int8 && "Update value should be 8-bit wide.");
    computeHash();
    if (next) {
        size = 1 + next->size;
    } else {
        size = 1;
    }
}

UpdateNode::~UpdateNode() {
}

int UpdateNode::compare(const UpdateNodePtr &b) const {
    if (int i = index.compare(b->index)) {
        return i;
    }
    return value.compare(b->value);
}

void UpdateNode::computeHash() {
    hashValue = index->hash() ^ value->hash();
    if (next) {
        hashValue ^= next->hash();
    }
}

///

UpdateList::UpdateList(ArrayPtr _root, const UpdateNodePtr _head)
    : root(_root), head(_head), m_refCount(0), m_hashValue(0) {
    computeHash();
}

void UpdateList::extend(const ref<Expr> &index, const ref<Expr> &value) {
    head = UpdateNode::create(head, index, value);
}

int UpdateList::compare(const UpdateListPtr &b) const {
    if (root->getName() != b->root->getName()) {
        return root->getName() < b->root->getName() ? -1 : 1;
    }

    // Check the root itself in case we have separate objects with the
    // same name.
    if (root != b->root) {
        return root < b->root ? -1 : 1;
    }

    if (getSize() < b->getSize()) {
        return -1;
    } else if (getSize() > b->getSize()) {
        return 1;
    }

    // XXX build comparison into update, make fast
    auto an = head, bn = b->head;
    for (; an && bn; an = an->getNext(), bn = bn->getNext()) {
        if (an == bn) { // exploit shared list structure
            return 0;
        } else {
            if (int res = an->compare(bn)) {
                return res;
            }
        }
    }
    assert(!an && !bn);
    return 0;
}

void UpdateList::computeHash() {
    unsigned res = 0;
    if (root) {
        for (unsigned i = 0, e = root->getName().size(); i != e; ++i) {
            res = (res * Expr::MAGIC_HASH_CONSTANT) + root->getName()[i];
        }
    }

    if (head) {
        res ^= head->hash();
    }

    m_hashValue = res;
}
