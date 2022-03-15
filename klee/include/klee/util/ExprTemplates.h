//===-- ExprUtil.h ----------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_UTIL_EXPRTEMPLATES_H
#define KLEE_UTIL_EXPRTEMPLATES_H

#include "klee/Expr.h"

#define E_SUB(a, b)       klee::SubExpr::create(a, b)
#define E_ZE(a, w)        klee::ZExtExpr::create(a, w)
#define E_SUBZE(a, b, w)  E_SUB(E_ZE(a, w), E_ZE(b, w))
#define E_AND(a, b)       klee::AndExpr::create(a, b)
#define E_OR(a, b)        klee::OrExpr::create(a, b)
#define E_LE(a, b)        klee::UleExpr::create(a, b)
#define E_LT(a, b)        klee::UltExpr::create(a, b)
#define E_EQ(a, b)        klee::EqExpr::create(a, b)
#define E_GT(a, b)        klee::UgtExpr::create(a, b)
#define E_GE(a, b)        klee::UgeExpr::create(a, b)
#define E_NOT(a)          klee::NotExpr::create(a)
#define E_NEQ(a, b)       E_NOT(E_EQ(a, b))
#define E_ITE(c, t, f)    klee::SelectExpr::create(c, t, f)
#define E_CONST(v, w)     klee::ConstantExpr::create(v, w)
#define E_MIN(a, b)       E_ITE(E_LT(a, b), a, b)
#define E_EXTR(v, off, w) klee::ExtractExpr::create(v, off, w)

#endif /* KLEE_UTIL_EXPRTEMPLATES_H */
