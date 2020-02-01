//===-- Constraints.cpp ---------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Constraints.h"

#include "klee/util/ExprPPrinter.h"
#include "klee/util/ExprVisitor.h"

#include <iostream>
#include <map>

namespace klee {

void ConstraintManager::addConstraint(const ref<Expr> e) {
    switch (e->getKind()) {
        case Expr::Constant:
            assert(cast<ConstantExpr>(e)->isTrue() && "attempt to add invalid (false) constraint");
            break;
        case Expr::And: {
            BinaryExpr *be = cast<BinaryExpr>(e);
            addConstraint(be->getKid(0));
            addConstraint(be->getKid(1));
            break;
        }
        default:
            head_ = head_->getOrCreate(e);
    }
}
} // namespace klee
