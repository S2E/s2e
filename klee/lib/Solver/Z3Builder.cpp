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

#include "Z3Builder.h"
#include <klee/Common.h>

#include "llvm/ADT/SmallString.h"
#include "llvm/Support/CommandLine.h"

#include "klee/SolverStats.h"

#include <boost/make_shared.hpp>

namespace {

// TODO: Make this a solver factory option and factor it out
llvm::cl::opt<bool> UseConstructHash("z3-use-hash-consing",
                                     llvm::cl::desc("Use hash consing during Z3 query construction."),
                                     llvm::cl::init(true));
} // namespace

using boost::make_shared;
using boost::shared_ptr;

namespace klee {

Z3Builder::Z3Builder(z3::context &context, Z3BuilderCache *cache) : context_(context), cache_(cache) {
}

Z3Builder::~Z3Builder() {
}

z3::expr Z3Builder::getOrMakeExpr(ref<Expr> e) {
    if (!UseConstructHash || isa<ConstantExpr>(e)) {
        return makeExpr(e);
    }

    z3::expr expr(context_);
    if (cache_->findExpr(e, expr))
        return expr;

    expr = makeExpr(e);
    cache_->insertExpr(e, expr);
    return expr;
}

z3::expr Z3Builder::makeExpr(ref<Expr> e) {
    ++stats::queryConstructs;

    switch (e->getKind()) {
        case Expr::Constant: {
            ConstantExpr *CE = cast<ConstantExpr>(e);
            unsigned width = CE->getWidth();
            if (width == 1)
                return context_.bool_val(CE->isTrue());
            if (width <= 64)
                return context_.bv_val((uint64_t) CE->getZExtValue(), width);

            // This is slower than concatenating 64-bit extractions, like STPBuilder
            // does, but the assumption is that it's quite infrequent.
            // TODO: Log these transformations.
            llvm::SmallString<32> const_repr;
            CE->getAPValue().toStringUnsigned(const_repr, 10);
            return context_.bv_val(const_repr.c_str(), width);
        }

        case Expr::Read: {
            return makeReadExpr(cast<ReadExpr>(e));
        }

        case Expr::Select: {
            SelectExpr *se = cast<SelectExpr>(e);
            // XXX: A bug in Clang prevents us from using z3::ite
            return z3::to_expr(context_, Z3_mk_ite(context_, getOrMakeExpr(se->getCondition()),
                                                   getOrMakeExpr(se->getTrue()), getOrMakeExpr(se->getFalse())));
        }

        case Expr::Concat: {
            ConcatExpr *ce = cast<ConcatExpr>(e);

            unsigned numKids = ce->getNumKids();
            z3::expr res = getOrMakeExpr(ce->getKid(numKids - 1));
            for (int i = numKids - 2; i >= 0; --i) {
                res = z3::to_expr(context_, Z3_mk_concat(context_, getOrMakeExpr(ce->getKid(i)), res));
            }
            return res;
        }

        case Expr::Extract: {
            ExtractExpr *ee = cast<ExtractExpr>(e);

            z3::expr src = getOrMakeExpr(ee->getExpr());
            if (ee->getWidth() == 1) {
                return z3::to_expr(context_, Z3_mk_extract(context_, ee->getOffset(), ee->getOffset(), src)) ==
                       context_.bv_val(1, 1);
            } else {
                return z3::to_expr(context_,
                                   Z3_mk_extract(context_, ee->getOffset() + ee->getWidth() - 1, ee->getOffset(), src));
            }
        }

            // Casting

        case Expr::ZExt: {
            CastExpr *ce = cast<CastExpr>(e);

            z3::expr src = getOrMakeExpr(ce->getSrc());
            if (src.is_bool()) {
                // XXX: A bug in Clang prevents us from using z3::ite
                return z3::to_expr(context_, Z3_mk_ite(context_, src, context_.bv_val(1, ce->getWidth()),
                                                       context_.bv_val(0, ce->getWidth())));
            } else {
                return z3::to_expr(context_, Z3_mk_zero_ext(context_, ce->getWidth() - src.get_sort().bv_size(), src));
            }
        }

        case Expr::SExt: {
            CastExpr *ce = cast<CastExpr>(e);

            z3::expr src = getOrMakeExpr(ce->getSrc());
            if (src.is_bool()) {
                return z3::to_expr(context_, Z3_mk_ite(context_, src, context_.bv_val(-1, ce->getWidth()),
                                                       context_.bv_val(0, ce->getWidth())));
            } else {
                return z3::to_expr(context_, Z3_mk_sign_ext(context_, ce->getWidth() - src.get_sort().bv_size(), src));
            }
        }

            // Arithmetic

        case Expr::Add: {
            AddExpr *ae = cast<AddExpr>(e);
            return getOrMakeExpr(ae->getLeft()) + getOrMakeExpr(ae->getRight());
        }

        case Expr::Sub: {
            SubExpr *se = cast<SubExpr>(e);

            // STP here takes an extra width parameter, wondering why...
            return getOrMakeExpr(se->getLeft()) - getOrMakeExpr(se->getRight());
        }

        case Expr::Mul: {
            MulExpr *me = cast<MulExpr>(e);

            // Again, we skip some optimizations from STPBuilder; just let the solver
            // do its own set of simplifications.
            return getOrMakeExpr(me->getLeft()) * getOrMakeExpr(me->getRight());
        }

        case Expr::UDiv: {
            UDivExpr *de = cast<UDivExpr>(e);
            return z3::udiv(getOrMakeExpr(de->getLeft()), getOrMakeExpr(de->getRight()));
        }

        case Expr::SDiv: {
            SDivExpr *de = cast<SDivExpr>(e);
            return getOrMakeExpr(de->getLeft()) / getOrMakeExpr(de->getRight());
        }

        case Expr::URem: {
            URemExpr *de = cast<URemExpr>(e);
            return z3::to_expr(context_,
                               Z3_mk_bvurem(context_, getOrMakeExpr(de->getLeft()), getOrMakeExpr(de->getRight())));
        }

        case Expr::SRem: {
            SRemExpr *de = cast<SRemExpr>(e);

            // Assuming the sign follows dividend (otherwise we should have used
            // the Z3_mk_bvsmod() call)
            return z3::to_expr(context_,
                               Z3_mk_bvsrem(context_, getOrMakeExpr(de->getLeft()), getOrMakeExpr(de->getRight())));
        }

            // Bitwise

        case Expr::Not: {
            NotExpr *ne = cast<NotExpr>(e);

            z3::expr expr = getOrMakeExpr(ne->getExpr());
            if (expr.is_bool()) {
                return !expr;
            } else {
                return ~expr;
            }
        }

        case Expr::And: {
            AndExpr *ae = cast<AndExpr>(e);

            z3::expr left = getOrMakeExpr(ae->getLeft());
            z3::expr right = getOrMakeExpr(ae->getRight());

            if (left.is_bool()) {
                return left && right;
            } else {
                return left & right;
            }
        }

        case Expr::Or: {
            OrExpr *oe = cast<OrExpr>(e);

            z3::expr left = getOrMakeExpr(oe->getLeft());
            z3::expr right = getOrMakeExpr(oe->getRight());

            if (left.is_bool()) {
                return left || right;
            } else {
                return left | right;
            }
        }

        case Expr::Xor: {
            XorExpr *xe = cast<XorExpr>(e);

            z3::expr left = getOrMakeExpr(xe->getLeft());
            z3::expr right = getOrMakeExpr(xe->getRight());

            if (left.is_bool()) {
                return z3::to_expr(context_, Z3_mk_xor(context_, left, right));
            } else {
                return left ^ right;
            }
        }

        case Expr::Shl: {
            ShlExpr *se = cast<ShlExpr>(e);
            return z3::to_expr(context_,
                               Z3_mk_bvshl(context_, getOrMakeExpr(se->getLeft()), getOrMakeExpr(se->getRight())));
        }

        case Expr::LShr: {
            LShrExpr *lse = cast<LShrExpr>(e);
            return z3::to_expr(context_,
                               Z3_mk_bvlshr(context_, getOrMakeExpr(lse->getLeft()), getOrMakeExpr(lse->getRight())));
        }

        case Expr::AShr: {
            AShrExpr *ase = cast<AShrExpr>(e);
            return z3::to_expr(context_,
                               Z3_mk_bvashr(context_, getOrMakeExpr(ase->getLeft()), getOrMakeExpr(ase->getRight())));
        }

            // Comparison

        case Expr::Eq: {
            EqExpr *ee = cast<EqExpr>(e);
            return getOrMakeExpr(ee->getLeft()) == getOrMakeExpr(ee->getRight());
        }

        case Expr::Ult: {
            UltExpr *ue = cast<UltExpr>(e);
            return z3::ult(getOrMakeExpr(ue->getLeft()), getOrMakeExpr(ue->getRight()));
        }

        case Expr::Ule: {
            UleExpr *ue = cast<UleExpr>(e);
            return z3::ule(getOrMakeExpr(ue->getLeft()), getOrMakeExpr(ue->getRight()));
        }

        case Expr::Slt: {
            SltExpr *se = cast<SltExpr>(e);
            return getOrMakeExpr(se->getLeft()) < getOrMakeExpr(se->getRight());
        }

        case Expr::Sle: {
            SleExpr *se = cast<SleExpr>(e);
            return getOrMakeExpr(se->getLeft()) <= getOrMakeExpr(se->getRight());
        }

// unused due to canonicalization
#if 0
    case Expr::Ne:
    case Expr::Ugt:
    case Expr::Uge:
    case Expr::Sgt:
    case Expr::Sge:
#endif

        default:
            pabort("unhandled Expr type");
    }
}

} /* namespace klee */
