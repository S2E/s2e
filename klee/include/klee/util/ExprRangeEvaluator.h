//===-- ExprRangeEvaluator.h ------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_EXPRRANGEEVALUATOR_H
#define KLEE_EXPRRANGEEVALUATOR_H

#include "klee/Expr.h"
#include "klee/util/Bits.h"

namespace klee {

/*
class ValueType {
public:
  ValueType(); // empty range
  ValueType(uint64_t value);
  ValueType(uint64_t min, uint64_t max);

  bool mustEqual(const uint64_t b);
  bool mustEqual(const ValueType &b);
  bool mayEqual(const uint64_t b);
  bool mayEqual(const ValueType &b);

  bool isFullRange(unsigned width);

  ValueType set_union(ValueType &);
  ValueType set_intersection(ValueType &);
  ValueType set_difference(ValueType &);

  ValueType binaryAnd(ValueType &);
  ValueType binaryOr(ValueType &);
  ValueType binaryXor(ValueType &);
  ValueType concat(ValueType &, unsigned width);
  ValueType add(ValueType &, unsigned width);
  ValueType sub(ValueType &, unsigned width);
  ValueType mul(ValueType &, unsigned width);
  ValueType udiv(ValueType &, unsigned width);
  ValueType sdiv(ValueType &, unsigned width);
  ValueType urem(ValueType &, unsigned width);
  ValueType srem(ValueType &, unsigned width);

  uint64_t min();
  uint64_t max();
  int64_t minSigned(unsigned width);
  int64_t maxSigned(unsigned width);
}
*/

template <class T> class ExprRangeEvaluator {
protected:
    /// getInitialReadRange - Return a range for the initial value of the given
    /// array (which may be constant), for the given range of indices.
    virtual T getInitialReadRange(const ArrayPtr &os, T index) = 0;

    T evalRead(const UpdateListPtr &ul, T index);

public:
    ExprRangeEvaluator() {
    }
    virtual ~ExprRangeEvaluator() {
    }

    T evaluate(const ref<Expr> &e);
};

template <class T> T ExprRangeEvaluator<T>::evalRead(const UpdateListPtr &ul, T index) {
    T res;

    for (auto un = ul->getHead(); un; un = un->getNext()) {
        T ui = evaluate(un->getIndex());

        if (ui.mustEqual(index)) {
            return res.set_union(evaluate(un->getValue()));
        } else if (ui.mayEqual(index)) {
            res = res.set_union(evaluate(un->getValue()));
            if (res.isFullRange(8)) {
                return res;
            }
        }
    }

    return res.set_union(getInitialReadRange(ul->getRoot(), index));
}

template <class T> T ExprRangeEvaluator<T>::evaluate(const ref<Expr> &e) {
    switch (e->getKind()) {
        case Expr::Constant:
            return T(cast<ConstantExpr>(e));

        case Expr::Read: {
            const ReadExpr *re = cast<ReadExpr>(e);
            T index = evaluate(re->getIndex());

            assert(re->getWidth() == Expr::Int8 && "unexpected multibyte read");

            return evalRead(re->getUpdates(), index);
        }

        case Expr::Select: {
            const SelectExpr *se = cast<SelectExpr>(e);
            T cond = evaluate(se->getCondition());

            if (cond.mustEqual(1)) {
                return evaluate(se->getTrue());
            } else if (cond.mustEqual(0)) {
                return evaluate(se->getFalse());
            } else {
                return evaluate(se->getTrue()).set_union(evaluate(se->getFalse()));
            }
        }

        // XXX these should be unrolled to ensure nice inline
        case Expr::Concat: {
            const Expr *ep = e.get();
            T res(0);
            for (unsigned i = 0; i < ep->getNumKids(); i++)
                res = res.concat(evaluate(ep->getKid(i)), 8);
            return res;
        }

            // Arithmetic

        case Expr::Add: {
            const BinaryExpr *be = cast<BinaryExpr>(e);
            unsigned width = be->getLeft()->getWidth();
            return evaluate(be->getLeft()).add(evaluate(be->getRight()), width);
        }
        case Expr::Sub: {
            const BinaryExpr *be = cast<BinaryExpr>(e);
            unsigned width = be->getLeft()->getWidth();
            return evaluate(be->getLeft()).sub(evaluate(be->getRight()), width);
        }
        case Expr::Mul: {
            const BinaryExpr *be = cast<BinaryExpr>(e);
            unsigned width = be->getLeft()->getWidth();
            return evaluate(be->getLeft()).mul(evaluate(be->getRight()), width);
        }
        case Expr::UDiv: {
            const BinaryExpr *be = cast<BinaryExpr>(e);
            unsigned width = be->getLeft()->getWidth();
            return evaluate(be->getLeft()).udiv(evaluate(be->getRight()), width);
        }
        case Expr::SDiv: {
            const BinaryExpr *be = cast<BinaryExpr>(e);
            unsigned width = be->getLeft()->getWidth();
            return evaluate(be->getLeft()).sdiv(evaluate(be->getRight()), width);
        }
        case Expr::URem: {
            const BinaryExpr *be = cast<BinaryExpr>(e);
            unsigned width = be->getLeft()->getWidth();
            return evaluate(be->getLeft()).urem(evaluate(be->getRight()), width);
        }
        case Expr::SRem: {
            const BinaryExpr *be = cast<BinaryExpr>(e);
            unsigned width = be->getLeft()->getWidth();
            return evaluate(be->getLeft()).srem(evaluate(be->getRight()), width);
        }

            // Binary

        case Expr::And: {
            const BinaryExpr *be = cast<BinaryExpr>(e);
            return evaluate(be->getLeft()).binaryAnd(evaluate(be->getRight()));
        }
        case Expr::Or: {
            const BinaryExpr *be = cast<BinaryExpr>(e);
            return evaluate(be->getLeft()).binaryOr(evaluate(be->getRight()));
        }
        case Expr::Xor: {
            const BinaryExpr *be = cast<BinaryExpr>(e);
            return evaluate(be->getLeft()).binaryXor(evaluate(be->getRight()));
        }
        case Expr::Shl: {
            //    BinaryExpr *be = cast<BinaryExpr>(e);
            //    unsigned width = be->getLeft()->getWidth();
            //    return evaluate(be->getLeft()).shl(evaluate(be->getRight()), width);
            break;
        }
        case Expr::LShr: {
            //    BinaryExpr *be = cast<BinaryExpr>(e);
            //    unsigned width = be->getLeft()->getWidth();
            //    return evaluate(be->getLeft()).lshr(evaluate(be->getRight()), width);
            break;
        }
        case Expr::AShr: {
            //    BinaryExpr *be = cast<BinaryExpr>(e);
            //    unsigned width = be->getLeft()->getWidth();
            //    return evaluate(be->getLeft()).ashr(evaluate(be->getRight()), width);
            break;
        }

            // Comparison

        case Expr::Eq: {
            const BinaryExpr *be = cast<BinaryExpr>(e);
            T left = evaluate(be->getLeft());
            T right = evaluate(be->getRight());

            if (left.mustEqual(right)) {
                return T(1);
            } else if (!left.mayEqual(right)) {
                return T(0);
            }
            break;
        }

        case Expr::Ult: {
            const BinaryExpr *be = cast<BinaryExpr>(e);
            T left = evaluate(be->getLeft());
            T right = evaluate(be->getRight());

            if (left.max() < right.min()) {
                return T(1);
            } else if (left.min() >= right.max()) {
                return T(0);
            }
            break;
        }
        case Expr::Ule: {
            const BinaryExpr *be = cast<BinaryExpr>(e);
            T left = evaluate(be->getLeft());
            T right = evaluate(be->getRight());

            if (left.max() <= right.min()) {
                return T(1);
            } else if (left.min() > right.max()) {
                return T(0);
            }
            break;
        }
        case Expr::Slt: {
            const BinaryExpr *be = cast<BinaryExpr>(e);
            T left = evaluate(be->getLeft());
            T right = evaluate(be->getRight());
            unsigned bits = be->getLeft()->getWidth();

            if (left.maxSigned(bits) < right.minSigned(bits)) {
                return T(1);
            } else if (left.minSigned(bits) >= right.maxSigned(bits)) {
                return T(0);
            }
            break;
        }
        case Expr::Sle: {
            const BinaryExpr *be = cast<BinaryExpr>(e);
            T left = evaluate(be->getLeft());
            T right = evaluate(be->getRight());
            unsigned bits = be->getLeft()->getWidth();

            if (left.maxSigned(bits) <= right.minSigned(bits)) {
                return T(1);
            } else if (left.minSigned(bits) > right.maxSigned(bits)) {
                return T(0);
            }
            break;
        }

        case Expr::Ne:
        case Expr::Ugt:
        case Expr::Uge:
        case Expr::Sgt:
        case Expr::Sge:
            assert(0 && "invalid expressions (uncanonicalized)");

        default:
            break;
    }

    return T(0, bits64::maxValueOfNBits(e->getWidth()));
}
} // namespace klee

#endif
