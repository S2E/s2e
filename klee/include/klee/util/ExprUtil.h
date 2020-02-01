//===-- ExprUtil.h ----------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_EXPRUTIL_H
#define KLEE_EXPRUTIL_H

#include <klee/Expr.h>
#include <vector>

namespace klee {
class Array;
class Expr;
class ReadExpr;
class ConcatExpr;
template <typename T> class ref;

/// Find all ReadExprs used in the expression DAG. If visitUpdates
/// is true then this will including those reachable by traversing
/// update lists. Note that this may be slow and return a large
/// number of results.
void findReads(ref<Expr> e, bool visitUpdates, std::vector<ref<ReadExpr>> &result);

/// Return a list of all unique symbolic objects referenced by the given
/// expression.
void findSymbolicObjects(ref<Expr> e, ArrayVec &results);

/// Return a list of all unique symbolic objects referenced by the
/// given expression range.
template <typename InputIterator> void findSymbolicObjects(InputIterator begin, InputIterator end, ArrayVec &results);

typedef std::vector<std::pair<const ref<ConcatExpr>, const ref<ConcatExpr>>> ConcatExprPairs;

bool getBinaryConcatExprPairs(const ref<Expr> &e, ConcatExprPairs &concatExprs);
bool getOrXorConcatExprPairs(const ref<Expr> &e, ConcatExprPairs &concatExprs);
bool getConcatExprPairs(const ref<Expr> &e, ConcatExprPairs &concatExprs);
} // namespace klee

#endif
