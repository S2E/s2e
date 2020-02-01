//===-- ImmutableTree.h -----------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __UTIL_IMMUTABLETREE_H__
#define __UTIL_IMMUTABLETREE_H__

#include <cassert>
#include <malloc.h>
#include <vector>

#include <boost/intrusive_ptr.hpp>

namespace klee {

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE = 1024> class ImmutableTree {
public:
    static size_t allocated;
    class iterator;

    typedef K key_type;
    typedef V value_type;
    typedef KOV key_of_value;
    typedef CMP key_compare;

public:
    ImmutableTree();
    ImmutableTree(const ImmutableTree &s);
    ~ImmutableTree();

    ImmutableTree &operator=(const ImmutableTree &s);

    bool empty() const;

    size_t count(const key_type &key) const; // always 0 or 1
    const value_type *lookup(const key_type &key) const;

    // find the last value less than or equal to key, or null if
    // no such value exists
    const value_type *lookup_previous(const key_type &key) const;

    const value_type &min() const;
    const value_type &max() const;
    size_t size() const;

    ImmutableTree insert(const value_type &value) const;
    ImmutableTree replace(const value_type &value) const;
    ImmutableTree remove(const key_type &key) const;
    ImmutableTree popMin(value_type &valueOut) const;
    ImmutableTree popMax(value_type &valueOut) const;

    iterator begin() const;
    iterator end() const;
    iterator find(const key_type &key) const;
    iterator lower_bound(const key_type &key) const;
    iterator upper_bound(const key_type &key) const;

    static size_t getAllocated() {
        return allocated;
    }

private:
    class Node;
    typedef boost::intrusive_ptr<Node> NodePtr;
    NodePtr node;

    ImmutableTree(const NodePtr &_node);
};

/***/

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
class ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::Node {
public:
    static Node terminator;
    static void *cache[NODE_CACHE_SIZE];
    static unsigned cache_top;

    NodePtr left, right;
    value_type value;
    unsigned height, references;

protected:
    Node(); // solely for creating the terminator node
    static NodePtr balance(const NodePtr &left, const value_type &value, const NodePtr &right);

    Node(const NodePtr &_left, const NodePtr &_right, const value_type &_value);

public:
    static NodePtr create(const NodePtr &left, const NodePtr &right, const value_type &value) {
        return NodePtr(new Node(left, right, value));
    }

    ~Node();

    friend void intrusive_ptr_add_ref(Node *ptr) {
        ++ptr->references;
    }

    friend void intrusive_ptr_release(Node *ptr) {
        if (--ptr->references == 0) {
            delete ptr;
        }
    }

    bool isTerminator();

    size_t size();
    NodePtr popMin(value_type &valueOut);
    NodePtr popMax(value_type &valueOut);
    NodePtr insert(const value_type &v);
    NodePtr replace(const value_type &v);
    NodePtr remove(const key_type &k);

    void *operator new(size_t size) {
        void *ret;
        if (cache_top == 0) {
            if (!(ret = malloc(size))) {
                throw std::bad_alloc();
            }
            return ret;
        }
        ret = cache[--cache_top];
        return ret;
    }

    void operator delete(void *ptr) {
        if (cache_top == NODE_CACHE_SIZE - 1) {
            free(ptr);
        } else {
            cache[cache_top++] = ptr;
        }
    }
};

// Should live somewhere else, this is a simple stack with maximum (dynamic)
// size.
template <typename T> class FixedStack {
    unsigned pos, max;
    T *elts;

public:
    FixedStack(unsigned _max) : pos(0), max(_max), elts(new T[max]) {
    }
    FixedStack(const FixedStack &b) : pos(b.pos), max(b.max), elts(new T[b.max]) {
        std::copy(b.elts, b.elts + pos, elts);
    }
    ~FixedStack() {
        delete[] elts;
    }

    void push_back(const T &elt) {
        elts[pos++] = elt;
    }
    void pop_back() {
        --pos;
    }
    bool empty() {
        return pos == 0;
    }
    T &back() {
        return elts[pos - 1];
    }

    FixedStack &operator=(const FixedStack &b) {
        assert(max == b.max);
        pos = b.pos;
        std::copy(b.elts, b.elts + pos, elts);
        return *this;
    }

    bool operator==(const FixedStack &b) {
        return (pos == b.pos && std::equal(elts, elts + pos, b.elts));
    }
    bool operator!=(const FixedStack &b) {
        return !(*this == b);
    }
};

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
class ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::iterator {
    friend class ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>;

private:
    NodePtr root; // so can back up from end
    FixedStack<NodePtr> stack;

public:
    iterator(NodePtr _root, bool atBeginning) : root(_root), stack(root->height) {
        if (atBeginning) {
            for (auto n = root; !n->isTerminator(); n = n->left)
                stack.push_back(n);
        }
    }
    iterator(const iterator &i) : root(i.root), stack(i.stack) {
    }
    ~iterator() {
    }

    iterator &operator=(const iterator &b) {
        b.root;
        root = b.root;
        stack = b.stack;
        return *this;
    }

    const value_type &operator*() {
        auto n = stack.back();
        return n->value;
    }

    const value_type *operator->() {
        auto n = stack.back();
        return &n->value;
    }

    bool operator==(const iterator &b) {
        return stack == b.stack;
    }
    bool operator!=(const iterator &b) {
        return stack != b.stack;
    }

    iterator &operator--() {
        if (stack.empty()) {
            for (NodePtr n = root; !n->isTerminator(); n = n->right)
                stack.push_back(n);
        } else {
            NodePtr n = stack.back();
            if (n->left->isTerminator()) {
                for (;;) {
                    NodePtr prev = n;
                    stack.pop_back();
                    if (stack.empty()) {
                        break;
                    } else {
                        n = stack.back();
                        if (prev == n->right)
                            break;
                    }
                }
            } else {
                stack.push_back(n->left);
                for (n = n->left->right; !n->isTerminator(); n = n->right)
                    stack.push_back(n);
            }
        }
        return *this;
    }

    iterator &operator++() {
        assert(!stack.empty());
        NodePtr n = stack.back();
        if (n->right->isTerminator()) {
            for (;;) {
                NodePtr prev = n;
                stack.pop_back();
                if (stack.empty()) {
                    break;
                } else {
                    n = stack.back();
                    if (prev == n->left)
                        break;
                }
            }
        } else {
            stack.push_back(n->right);
            for (n = n->right->left; !n->isTerminator(); n = n->left)
                stack.push_back(n);
        }
        return *this;
    }
};

/***/

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
typename ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::Node
    ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::Node::terminator;

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
void *ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::Node::cache[NODE_CACHE_SIZE];

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
unsigned ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::Node::cache_top = 0;

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
size_t ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::allocated = 0;

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::Node::Node()
    : left(&terminator), right(&terminator), height(0), references(3) {
    assert(this == &terminator);
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::Node::Node(const NodePtr &_left, const NodePtr &_right,
                                                           const value_type &_value)
    : left(_left), right(_right), value(_value), height(std::max(left->height, right->height) + 1), references(0) {
    ++allocated;
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::Node::~Node() {
    --allocated;
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
inline bool ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::Node::isTerminator() {
    return this == &terminator;
}

/***/

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
typename ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::NodePtr
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::Node::balance(const NodePtr &left, const value_type &value,
                                                              const NodePtr &right) {
    if (left->height > right->height + 2) {
        auto ll = left->left;
        auto lr = left->right;
        if (ll->height >= lr->height) {
            auto nlr = Node::create(lr, right, value);
            auto res = Node::create(ll, nlr, left->value);
            return res;
        } else {
            auto lrl = lr->left;
            auto lrr = lr->right;
            auto nll = Node::create(ll, lrl, left->value);
            auto nlr = Node::create(lrr, right, value);
            auto res = Node::create(nll, nlr, lr->value);
            return res;
        }
    } else if (right->height > left->height + 2) {
        auto rl = right->left;
        auto rr = right->right;
        if (rr->height >= rl->height) {
            auto nrl = Node::create(left, rl, value);
            auto res = Node::create(nrl, rr, right->value);
            return res;
        } else {
            auto rll = rl->left;
            auto rlr = rl->right;
            auto nrl = Node::create(left, rll, value);
            auto nrr = Node::create(rlr, rr, right->value);
            auto res = Node::create(nrl, nrr, rl->value);
            return res;
        }
    } else {
        return Node::create(left, right, value);
    }
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
size_t ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::Node::size() {
    if (isTerminator()) {
        return 0;
    } else {
        return left->size() + 1 + right->size();
    }
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
typename ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::NodePtr
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::Node::popMin(value_type &valueOut) {
    if (left->isTerminator()) {
        valueOut = value;
        return right;
    } else {
        return balance(left->popMin(valueOut), value, right);
    }
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
typename ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::NodePtr
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::Node::popMax(value_type &valueOut) {
    if (right->isTerminator()) {
        valueOut = value;
        return left;
    } else {
        return balance(left, value, right->popMax(valueOut));
    }
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
typename ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::NodePtr
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::Node::insert(const value_type &v) {
    if (isTerminator()) {
        return Node::create(&terminator, &terminator, v);
    } else {
        if (key_compare()(key_of_value()(v), key_of_value()(value))) {
            return balance(left->insert(v), value, right);
        } else if (key_compare()(key_of_value()(value), key_of_value()(v))) {
            return balance(left, value, right->insert(v));
        } else {
            return this;
        }
    }
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
typename ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::NodePtr
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::Node::replace(const value_type &v) {
    if (isTerminator()) {
        return Node::create(&terminator, &terminator, v);
    } else {
        if (key_compare()(key_of_value()(v), key_of_value()(value))) {
            return balance(left->replace(v), value, right);
        } else if (key_compare()(key_of_value()(value), key_of_value()(v))) {
            return balance(left, value, right->replace(v));
        } else {
            return Node::create(left, right, v);
        }
    }
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
typename ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::NodePtr
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::Node::remove(const key_type &k) {
    if (isTerminator()) {
        return this;
    } else {
        if (key_compare()(k, key_of_value()(value))) {
            return balance(left->remove(k), value, right);
        } else if (key_compare()(key_of_value()(value), k)) {
            return balance(left, value, right->remove(k));
        } else {
            if (left->isTerminator()) {
                return right;
            } else if (right->isTerminator()) {
                return left;
            } else {
                value_type min;
                auto nr = right->popMin(min);
                return balance(left, min, nr);
            }
        }
    }
}

/***/

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::ImmutableTree() : node(&Node::terminator) {
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::ImmutableTree(const NodePtr &_node) : node(_node) {
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::ImmutableTree(const ImmutableTree &s) : node(s.node) {
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::~ImmutableTree() {
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE> &
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::operator=(const ImmutableTree &s) {
    auto n = s.node;
    node = n;
    return *this;
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
bool ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::empty() const {
    return node->isTerminator();
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
size_t ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::count(const key_type &k) const {
    auto n = node;
    while (!n->isTerminator()) {
        key_type key = key_of_value()(n->value);
        if (key_compare()(k, key)) {
            n = n->left;
        } else if (key_compare()(key, k)) {
            n = n->right;
        } else {
            return 1;
        }
    }
    return 0;
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
const typename ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::value_type *
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::lookup(const key_type &k) const {
    auto n = node;
    while (!n->isTerminator()) {
        key_type key = key_of_value()(n->value);
        if (key_compare()(k, key)) {
            n = n->left;
        } else if (key_compare()(key, k)) {
            n = n->right;
        } else {
            return &n->value;
        }
    }
    return 0;
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
const typename ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::value_type *
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::lookup_previous(const key_type &k) const {
    auto n = node;
    NodePtr result = nullptr;
    while (!n->isTerminator()) {
        key_type key = key_of_value()(n->value);
        if (key_compare()(k, key)) {
            n = n->left;
        } else if (key_compare()(key, k)) {
            result = n;
            n = n->right;
        } else {
            return &n->value;
        }
    }
    return result ? &result->value : 0;
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
const typename ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::value_type &
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::min() const {
    auto n = node;
    assert(!n->isTerminator());
    while (!n->left->isTerminator())
        n = n->left;
    return n->value;
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
const typename ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::value_type &
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::max() const {
    auto n = node;
    assert(!n->isTerminator());
    while (!n->right->isTerminator())
        n = n->right;
    return n->value;
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
size_t ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::size() const {
    return node->size();
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::insert(const value_type &value) const {
    return ImmutableTree(node->insert(value));
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::replace(const value_type &value) const {
    return ImmutableTree(node->replace(value));
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::remove(const key_type &key) const {
    return ImmutableTree(node->remove(key));
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::popMin(value_type &valueOut) const {
    return ImmutableTree(node->popMin(valueOut));
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::popMax(value_type &valueOut) const {
    return ImmutableTree(node->popMax(valueOut));
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
inline typename ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::iterator
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::begin() const {
    return iterator(node, true);
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
inline typename ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::iterator
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::end() const {
    return iterator(node, false);
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
inline typename ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::iterator
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::find(const key_type &key) const {
    iterator end(node, false), it = lower_bound(key);
    if (it == end || key_compare()(key, key_of_value()(*it))) {
        return end;
    } else {
        return it;
    }
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
inline typename ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::iterator
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::lower_bound(const key_type &k) const {
    // XXX ugh this doesn't have to be so ugly does it?
    iterator it(node, false);
    for (auto root = node; !root->isTerminator();) {
        it.stack.push_back(root);
        if (key_compare()(k, key_of_value()(root->value))) {
            root = root->left;
        } else if (key_compare()(key_of_value()(root->value), k)) {
            root = root->right;
        } else {
            return it;
        }
    }
    // it is now beginning or first element < k
    if (!it.stack.empty()) {
        auto last = it.stack.back();
        if (key_compare()(key_of_value()(last->value), k))
            ++it;
    }
    return it;
}

template <class K, class V, class KOV, class CMP, unsigned int NODE_CACHE_SIZE>
typename ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::iterator
ImmutableTree<K, V, KOV, CMP, NODE_CACHE_SIZE>::upper_bound(const key_type &key) const {
    iterator end(node, false), it = lower_bound(key);
    if (it != end && !key_compare()(key, key_of_value()(*it))) // no need to loop, no duplicates
        ++it;
    return it;
}
} // namespace klee

#endif
