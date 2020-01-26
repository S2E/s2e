//===-- ExprUtil.cpp ------------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/util/ExprUtil.h"
#include "klee/util/ExprHashMap.h"

#include "klee/Expr.h"

#include "klee/util/ExprVisitor.h"

#include <set>

using namespace klee;

void klee::findReads(ref<Expr> e, bool visitUpdates, std::vector<ref<ReadExpr>> &results) {
    // Invariant: \forall_{i \in stack} !i.isConstant() && i \in visited
    std::vector<ref<Expr>> stack;
    ExprHashSet visited;
    std::set<const UpdateNode *> updates;

    if (!isa<ConstantExpr>(e)) {
        visited.insert(e);
        stack.push_back(e);
    }

    while (!stack.empty()) {
        ref<Expr> top = stack.back();
        stack.pop_back();

        if (ReadExpr *re = dyn_cast<ReadExpr>(top)) {
            // We memoized so can just add to list without worrying about
            // repeats.
            results.push_back(re);

            if (!isa<ConstantExpr>(re->getIndex()) && visited.insert(re->getIndex()).second)
                stack.push_back(re->getIndex());

            if (visitUpdates) {
                // XXX this is probably suboptimal. We want to avoid a potential
                // explosion traversing update lists which can be quite
                // long. However, it seems silly to hash all of the update nodes
                // especially since we memoize all the expr results anyway. So
                // we take a simple approach of memoizing the results for the
                // head, which often will be shared among multiple nodes.
                if (updates.insert(re->getUpdates()->getHead().get()).second) {
                    for (auto un = re->getUpdates()->getHead(); un; un = un->getNext()) {
                        if (!isa<ConstantExpr>(un->getIndex()) && visited.insert(un->getIndex()).second)
                            stack.push_back(un->getIndex());
                        if (!isa<ConstantExpr>(un->getValue()) && visited.insert(un->getValue()).second)
                            stack.push_back(un->getValue());
                    }
                }
            }
        } else if (!isa<ConstantExpr>(top)) {
            Expr *e = top.get();
            for (unsigned i = 0; i < e->getNumKids(); i++) {
                ref<Expr> k = e->getKid(i);
                if (!isa<ConstantExpr>(k) && visited.insert(k).second)
                    stack.push_back(k);
            }
        }
    }
}

///

namespace klee {

class SymbolicObjectFinder : public ExprVisitor {
protected:
    Action visitRead(const ReadExpr &re) {
        auto ul = re.getUpdates();

        // XXX should we memo better than what ExprVisitor is doing for us?
        for (auto un = ul->getHead(); un; un = un->getNext()) {
            visit(un->getIndex());
            visit(un->getValue());
        }

        if (ul->getRoot()->isSymbolicArray()) {
            if (results.insert(ul->getRoot()).second) {
                objects.push_back(ul->getRoot());
            }
        }

        return Action::doChildren();
    }

public:
    std::unordered_set<ArrayPtr, ArrayHash> results;
    ArrayVec &objects;

    SymbolicObjectFinder(ArrayVec &_objects) : objects(_objects) {
    }
};
} // namespace klee

template <typename InputIterator>
void klee::findSymbolicObjects(InputIterator begin, InputIterator end, ArrayVec &results) {
    SymbolicObjectFinder of(results);
    for (; begin != end; ++begin)
        of.visit(*begin);
}

void klee::findSymbolicObjects(ref<Expr> e, ArrayVec &results) {
    findSymbolicObjects(&e, &e + 1, results);
}

typedef std::vector<ref<Expr>>::iterator A;
template void klee::findSymbolicObjects<A>(A, A, ArrayVec &);

typedef std::set<ref<Expr>>::iterator B;
template void klee::findSymbolicObjects<B>(B, B, ArrayVec &);

///

namespace klee {

/// \brief Extract concat expression pairs from a binary expression
///
/// If \param e is a binary expression, and both its kids are concat expressions,
/// they will be placed into \param concatExprs and function will return true.
/// Otherwise, false is returned and \param concatExprs is not modified.
///
/// \param e input expression
/// \param concatExprs place to store extracted expression pairs
/// \returns false if no Concat expressions were found, otherwise true
///
bool getBinaryConcatExprPairs(const ref<Expr> &e, ConcatExprPairs &concatExprs) {
    if (!isa<BinaryExpr>(e)) {
        return false;
    }

    const ref<Expr> left = e->getKid(0);
    const ref<Expr> right = e->getKid(1);

    if (isa<ConcatExpr>(left) && isa<ConcatExpr>(right)) {
        concatExprs.push_back(std::make_pair(dyn_cast<ConcatExpr>(left), dyn_cast<ConcatExpr>(right)));
        return true;
    }

    return false;
}

/// \brief Extract concat expression pairs from the (Or (Xor() Xor())) expression
///
/// If \param e is has a (Or (Xor() Xor())) form, try extracting concat expression pairs
/// from each Xor kid. If both Xor kids contained concat expressions, they will be
/// placed into \param concatExprs and function will return true.
/// Otherwise, false is returned and \param concatExprs is not modified.
///
/// \param e input expression
/// \param concatExprs place to store extracted expression pairs
/// \returns false if no Concat expressions were found, otherwise true
///
bool getOrXorConcatExprPairs(const ref<Expr> &e, ConcatExprPairs &concatExprs) {
    if (!isa<OrExpr>(e)) {
        return false;
    }

    const ref<Expr> left = e->getKid(0);
    const ref<Expr> right = e->getKid(1);

    if (isa<XorExpr>(left) && isa<XorExpr>(right)) {
        ConcatExprPairs temp;
        if (getBinaryConcatExprPairs(left, temp) && getBinaryConcatExprPairs(right, temp)) {
            std::copy(temp.begin(), temp.end(), std::back_inserter(concatExprs));
            return true;
        }
    }

    return false;
}

/// \brief Extract concat expression pairs that have to match each other
///
/// Extract concat expression pairs that have to match each other in order
/// to evaluate expression \param e to True.
/// On successfull extraction, they will be placed into \param concatExprs
/// and function will return true.
/// Otherwise, false is returned and \param concatExprs is not modified.
///
/// Following \param e expression types are supported:
///   - (Eq (Concat ...) (Concat ...))
///   - (Eq (0) (Or (Xor (Concat ...) (Concat ...)) (Xor (Concat ...) (Concat ...))))
///
/// \param e input expression
/// \param concatExprs place to store extracted expression pairs
/// \returns false if no Concat expressions were found, otherwise true
///
bool getConcatExprPairs(const ref<Expr> &e, ConcatExprPairs &concatExprs) {
    if (!isa<EqExpr>(e)) {
        return false;
    }

    const ref<Expr> left = e->getKid(0);
    const ref<Expr> right = e->getKid(1);

    if (getBinaryConcatExprPairs(e, concatExprs)) {
        // (Eq (Concat ...) (Concat ...))
        return true;
    } else if (left->isZero() && isa<OrExpr>(right)) {
        // (Eq (0) (Or (Xor ...) (Xor ...)))
        return getOrXorConcatExprPairs(right, concatExprs);
    }

    return false;
}
} // namespace klee
