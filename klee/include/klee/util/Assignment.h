//===-- Assignment.h --------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_UTIL_ASSIGNMENT_H
#define KLEE_UTIL_ASSIGNMENT_H

#include <map>

#include "klee/util/ExprEvaluator.h"

namespace klee {
class Array;

class Assignment;
using AssignmentPtr = std::shared_ptr<Assignment>;
using AssignmentConstPtr = std::shared_ptr<const Assignment>;

class Assignment {
public:
    typedef std::map<ArrayPtr, std::vector<unsigned char>, ArrayLt> bindings_ty;
    typedef ExprHashMap<ref<Expr>> ExpressionCache;
    typedef std::unordered_map<ArrayPtr, UpdateListPtr, ArrayHash> UpdateListCache;

    bool allowFreeValues;
    bindings_ty bindings;
    mutable ExpressionCache expressionCache;
    mutable UpdateListCache updateListCache;
    mutable uint64_t cacheHits, cacheMisses;

private:
    Assignment(bool _allowFreeValues = false) : allowFreeValues(_allowFreeValues), cacheHits(0), cacheMisses(0) {
    }

    Assignment(ArrayVec &objects, std::vector<std::vector<unsigned char>> &values, bool _allowFreeValues = false)
        : allowFreeValues(_allowFreeValues) {
        auto valIt = values.begin();
        for (const auto &it : objects) {
            auto os = it;
            std::vector<unsigned char> &arr = *valIt;
            bindings.insert(std::make_pair(os, arr));
            ++valIt;
        }
    }

public:
    ref<Expr> evaluate(const ArrayPtr &mo, unsigned index) const;
    ref<Expr> evaluate(ref<Expr> e) const;

    void add(const ArrayPtr &object, const std::vector<unsigned char> &value) {
        bindings.insert(std::make_pair(object, value));
    }

    void clear() {
        bindings.clear();
        expressionCache.clear();
        updateListCache.clear();
        cacheHits = 0;
        cacheMisses = 0;
    }

    template <typename InputIterator> bool satisfies(InputIterator begin, InputIterator end);

    static AssignmentPtr create(bool _allowFreeValues = false) {
        return AssignmentPtr(new Assignment(_allowFreeValues));
    }

    static AssignmentPtr create(ArrayVec &objects, std::vector<std::vector<unsigned char>> &values,
                                bool _allowFreeValues = false) {
        return AssignmentPtr(new Assignment(objects, values, _allowFreeValues));
    }

    static AssignmentPtr create(const AssignmentPtr &a) {
        return AssignmentPtr(new Assignment(*a));
    }
};

/***/
class CachedAssignmentEvaluator {
    const Assignment &m_assignment;

    ref<Expr> evaluateActual(const ref<Expr> &expr);
    ref<Expr> evaluateRead(const ref<ReadExpr> &expr);
    ref<Expr> evaluateSelect(const ref<SelectExpr> &expr);
    ref<Expr> evaluateAnd(const ref<AndExpr> &expr);
    ref<Expr> evaluateUSDivRem(const ref<Expr> &expr);
    UpdateListPtr rewriteUpdatesUncached(const UpdateListPtr &ul);

public:
    CachedAssignmentEvaluator(const Assignment &a) : m_assignment(a) {
    }

    ref<Expr> visit(const ref<Expr> &e);
};

/***/
class AssignmentEvaluator : public ExprEvaluator {
    const Assignment &a;

protected:
    ref<Expr> getInitialValue(const ArrayPtr &mo, unsigned index) {
        return a.evaluate(mo, index);
    }

public:
    AssignmentEvaluator(const Assignment &_a) : a(_a) {
    }
};

/***/

inline ref<Expr> Assignment::evaluate(const ArrayPtr &array, unsigned index) const {
    // assert(index < array->size);
    bindings_ty::const_iterator it = bindings.find(array);
    if (it != bindings.end() && index < it->second.size()) {
        return ConstantExpr::alloc(it->second[index], Expr::Int8);
    } else {
        if (allowFreeValues) {
            return ReadExpr::create(UpdateList::create(array, 0), ConstantExpr::alloc(index, Expr::Int32));
        } else {
            return ConstantExpr::alloc(0, Expr::Int8);
        }
    }
}

inline ref<Expr> Assignment::evaluate(ref<Expr> e) const {
    CachedAssignmentEvaluator v(*this);
    return v.visit(e);
}

template <typename InputIterator> inline bool Assignment::satisfies(InputIterator begin, InputIterator end) {
    CachedAssignmentEvaluator v(*this);
    for (; begin != end; ++begin)
        if (!v.visit(*begin)->isTrue())
            return false;
    return true;
}
} // namespace klee

#endif
