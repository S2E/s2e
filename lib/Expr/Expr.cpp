//===-- Expr.cpp ----------------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Expr.h"
#include <klee/Common.h>

#include "llvm/Support/CommandLine.h"
// FIXME: We shouldn't need this once fast constant support moves into
// Core. If we need to do arithmetic, we probably want to use APInt.
#include "klee/Internal/Support/IntEvaluation.h"

#include <llvm/ADT/Hashing.h>
#include <llvm/Support/raw_os_ostream.h>
#include "klee/util/ExprPPrinter.h"

#include <iostream>
#include <sstream>

using namespace klee;
using namespace llvm;

namespace {
cl::opt<bool> ConstArrayOpt("const-array-opt", cl::init(true),
                            cl::desc("Enable various optimizations involving all-constant arrays."));
}

/***/

///
/// \brief Simplify the pattern that results from an unaligned read to memory.
///
/// An unaligned read is a read whose start address is not a multiple of the access size.
/// Unaligned reads are broken down into two aligned reads which are then
/// shifted and merged, which results in an expression that looks like this:
///
/// (v7 v6 v5 v4) << 0x18 || (v3 v2 v1 v0) >> 0x8)
///
/// v0..v7 represent byte-sized variables that are concatenated with ConcatExpr.
/// This function will simplify the expression above to v4 v3 v2 v1.
///
/// \param unalignedRead the expression to simplify
/// \return the simplified expression if successful, the original one otherwise
///
static ref<Expr> SimplifyUnalignedReadPattern(const ref<Expr> &unalignedRead) {
    // Check the shape of the expression, which must look like this:
    // or(shl(a, b), lshr(c, d))
    const OrExpr *ore = dyn_cast<const OrExpr>(unalignedRead);
    if (!ore) {
        return unalignedRead;
    }

    const ShlExpr *shle = dyn_cast<const ShlExpr>(ore->getLeft());
    const LShrExpr *lshre = dyn_cast<const LShrExpr>(ore->getRight());
    if (!shle || !lshre) {
        shle = dyn_cast<const ShlExpr>(ore->getRight());
        lshre = dyn_cast<const LShrExpr>(ore->getLeft());
        if (!shle || !lshre) {
            return unalignedRead;
        }
    }

    const ConstantExpr *s1 = dyn_cast<const ConstantExpr>(shle->getRight());
    const ConstantExpr *s2 = dyn_cast<const ConstantExpr>(lshre->getRight());
    if (!s1 || !s2) {
        return unalignedRead;
    }

    auto s11 = s1->getZExtValue();
    auto s22 = s2->getZExtValue();

    if (s11 % 8 || s22 % 8) {
        return unalignedRead;
    }

    auto w = unalignedRead->getWidth();
    if ((s11 + s22) != w) {
        return unalignedRead;
    }

    std::vector<ref<Expr>> bytes;

    for (unsigned i = 0; i < w - s11; i += 8) {
        auto e = ExtractExpr::create(shle->getLeft(), w - 8 - s11 - i, Expr::Int8);
        bytes.push_back(e);
    }

    for (int i = w - 8; i >= (int) s22; i -= 8) {
        auto e = ExtractExpr::create(lshre->getLeft(), i, Expr::Int8);
        bytes.push_back(e);
    }

    assert(bytes.size() == w / 8);

    return ConcatExpr::createN(bytes.size(), &bytes[0]);
}

///
/// \brief Transform ExtractN(a, LShr(b, c)) to ExtractN(b, c)
///
/// N is the size of the resulting expression
/// a is the offset to start extracting from (must be 0 for now)
/// b is the shifted expression
/// c is the amount to shift
///
/// For example, the following expression:
/// (Extract w8 0 (LShr w32 (Concat w32 (Read w8 0x0 v0)
///                                      (Concat w24 (Read w8 0x0 v1)
///                                                  (Concat w16 (Read w8 0x0 v2) (Read w8 0x0 v3))))
///                          0x10))
///
/// will be simplified to:
///
/// (Extract w8 0x10 (Concat w32 (Read w8 0x0 v0)
///                           (Concat w24 (Read w8 0x0 v1)
///                           (Concat w16 (Read w8 0x0 v2) (Read w8 0x0 v3))))
///
/// This form will make it easy for BitfieldSimplifier to transform it into:
/// (Read w8 0x0 v1)
///
/// \param e the expression to simplify
/// \return the simplifed expression if successful, the original one otherwise
///
static ref<Expr> SimplifyExtractLShr(const ref<Expr> &e) {
    const ExtractExpr *extract = dyn_cast<ExtractExpr>(e);
    if (!extract) {
        return e;
    }

    if (extract->getOffset()) {
        // This is a bit more complicated, implement it in case we encouter it.
        return e;
    }

    const LShrExpr *lshr = dyn_cast<const LShrExpr>(e->getKid(0));
    if (!lshr) {
        return e;
    }

    const ConstantExpr *shift = dyn_cast<const ConstantExpr>(lshr->getRight());
    if (!shift || shift->getWidth() > Expr::Int64) {
        return e;
    }

    auto offset = shift->getZExtValue();
    if (offset % 8) {
        return e;
    }

    // The shift amount may be larger than the type itself
    if (!(offset + e->getWidth() <= lshr->getLeft()->getWidth())) {
        return e;
    }

    return ExtractExpr::create(lshr->getLeft(), offset, e->getWidth());
}

///
/// \brief Simplify Extract_z(0, And_x(ZExt_x(X_y), mask))
///
/// This eliminates needless pattern of extract, and, and zero extension
/// that is generated by some LLVM workloads.
///
/// - x, y, and z are sizes in bits
/// - X_y is the inner-most expression of size y
/// - mask is a bit mask of the form 0xff (or 1<<y - 1)
/// - If 1<<z == 1<<y == (mask+1) then return X_y
///
static ref<Expr> SimplifyExtractAndZext(const ref<Expr> &e) {
    const ExtractExpr *extr = dyn_cast<const ExtractExpr>(e);
    if (!extr || (extr->getOffset() != 0)) {
        return e;
    }

    const AndExpr *andx = dyn_cast<const AndExpr>(extr->getExpr());
    if (!andx) {
        return e;
    }

    const ZExtExpr *zext = dyn_cast<const ZExtExpr>(andx->getKid(0));
    if (!zext) {
        return e;
    }

    const ConstantExpr *mask = dyn_cast<const ConstantExpr>(andx->getKid(1));
    if (!mask) {
        return e;
    }

    const auto &X = zext->getKid(0);

    if (mask->getZExtValue() != bitmask<uint64_t>(X->getWidth())) {
        return e;
    }

    if (extr->getWidth() == X->getWidth()) {
        return X;
    }

    return e;
}

// returns 0 if b is structurally equal to *this
int Expr::compare(const Expr &b) const {
    if (this == &b)
        return 0;

    Kind ak = getKind(), bk = b.getKind();
    if (ak != bk)
        return (ak < bk) ? -1 : 1;

    if (hashValue != b.hashValue)
        return (hashValue < b.hashValue) ? -1 : 1;

    if (int res = compareContents(b))
        return res;

    unsigned aN = getNumKids();
    for (unsigned i = 0; i < aN; i++)
        if (int res = getKid(i).compare(b.getKid(i)))
            return res;

    return 0;
}

void Expr::printKind(llvm::raw_ostream &os, Kind k) {
    switch (k) {
#define X(C)      \
    case C:       \
        os << #C; \
        break
        X(Constant);
        X(Read);
        X(Select);
        X(Concat);
        X(Extract);
        X(ZExt);
        X(SExt);
        X(Add);
        X(Sub);
        X(Mul);
        X(UDiv);
        X(SDiv);
        X(URem);
        X(SRem);
        X(Not);
        X(And);
        X(Or);
        X(Xor);
        X(Shl);
        X(LShr);
        X(AShr);
        X(Eq);
        X(Ne);
        X(Ult);
        X(Ule);
        X(Ugt);
        X(Uge);
        X(Slt);
        X(Sle);
        X(Sgt);
        X(Sge);
#undef X
        default:
            pabort("invalid kind");
    }
}

////////
//
// Simple hash functions for various kinds of Exprs
//
///////

unsigned ConstantExpr::computeHash() {
    hashValue = hash_value(value) ^ (getWidth() * MAGIC_HASH_CONSTANT);
    return hashValue;
}

void CastExpr::computeHash() {
    unsigned res = getWidth() * Expr::MAGIC_HASH_CONSTANT;
    hashValue = res ^ src->hash() * Expr::MAGIC_HASH_CONSTANT;
}

void ExtractExpr::computeHash() {
    unsigned res = offset * Expr::MAGIC_HASH_CONSTANT;
    res ^= getWidth() * Expr::MAGIC_HASH_CONSTANT;
    res ^= getKind();
    hashValue = res ^ expr->hash() * Expr::MAGIC_HASH_CONSTANT;
}

void ReadExpr::computeHash() {
    unsigned res = index->hash() * Expr::MAGIC_HASH_CONSTANT;
    res ^= updates->hash();
    res ^= getKind();
    hashValue = res;
}

void NotExpr::computeHash() {
    hashValue = expr->hash() * Expr::MAGIC_HASH_CONSTANT * Expr::Not;
    hashValue ^= getKind();
}

void Expr::printWidth(llvm::raw_ostream &os, Width width) {
    switch (width) {
        case Expr::Bool:
            os << "Expr::Bool";
            break;
        case Expr::Int8:
            os << "Expr::Int8";
            break;
        case Expr::Int16:
            os << "Expr::Int16";
            break;
        case Expr::Int32:
            os << "Expr::Int32";
            break;
        case Expr::Int64:
            os << "Expr::Int64";
            break;
        default:
            os << "<invalid type: " << (unsigned) width << ">";
    }
}

ref<Expr> Expr::createImplies(const ref<Expr> &hyp, const ref<Expr> &conc) {
    return OrExpr::create(Expr::createIsZero(hyp), conc);
}

ref<Expr> Expr::createIsZero(const ref<Expr> &e) {
    return EqExpr::create(e, ConstantExpr::create(0, e->getWidth()));
}

bool Expr::isIsZeroOf(const ref<Expr> &e) const {
    if (const EqExpr *ee = dyn_cast<const EqExpr>(this))
        if (ee->getLeft()->isZero() && ee->getRight() == e)
            return true;
    return false;
}

bool Expr::isNegationOf(const ref<Expr> &e) const {
    return isIsZeroOf(e) || e->isIsZeroOf(ref<Expr>(const_cast<Expr *>(this)));
}

void Expr::print(llvm::raw_ostream &os) const {
    ExprPPrinter::printSingleExpr(os, const_cast<Expr *>(this));
}

void Expr::dump() const {
    llvm::raw_os_ostream os(std::cerr);
    this->print(os);
    os << '\n';
}

/***/

ref<Expr> ConstantExpr::fromMemory(void *address, Width width) {
    switch (width) {
        default:
            pabort("invalid type");
        case Expr::Bool:
            return ConstantExpr::create(*((uint8_t *) address), width);
        case Expr::Int8:
            return ConstantExpr::create(*((uint8_t *) address), width);
        case Expr::Int16:
            return ConstantExpr::create(*((uint16_t *) address), width);
        case Expr::Int32:
            return ConstantExpr::create(*((uint32_t *) address), width);
        case Expr::Int64:
            return ConstantExpr::create(*((uint64_t *) address), width);
        case Expr::Int128:
            return ConstantExpr::create(*((__uint128_t *) address), width);
            // FIXME: Should support long double, at least.
    }
}

void ConstantExpr::toMemory(void *address) {
    switch (getWidth()) {
        default:
            pabort("invalid type");
        case Expr::Bool:
            *((uint8_t *) address) = getZExtValue(1);
            break;
        case Expr::Int8:
            *((uint8_t *) address) = getZExtValue(8);
            break;
        case Expr::Int16:
            *((uint16_t *) address) = getZExtValue(16);
            break;
        case Expr::Int32:
            *((uint32_t *) address) = getZExtValue(32);
            break;
        case Expr::Int64:
            *((uint64_t *) address) = getZExtValue(64);
            break;
        case Expr::Int128:
            *((__uint128_t *) address) = getZExtValue(128);
            break;
            // FIXME: Should support long double, at least.
    }
}

void ConstantExpr::toString(std::string &Res, int Base) const {
    Res = value.toString(Base, false);
}

ref<ConstantExpr> ConstantExpr::Concat(const ref<ConstantExpr> &RHS) {
    Expr::Width W = getWidth() + RHS->getWidth();
    APInt Tmp(value);
    Tmp = Tmp.zext(W);
    Tmp <<= RHS->getWidth();
    Tmp |= APInt(RHS->value).zext(W);

    return ConstantExpr::alloc(Tmp);
}

ref<ConstantExpr> ConstantExpr::Extract(unsigned Offset, Width W) {
    return ConstantExpr::alloc(APInt(value.ashr(Offset)).zextOrTrunc(W));
}

ref<ConstantExpr> ConstantExpr::ZExt(Width W) {
    return ConstantExpr::alloc(APInt(value).zextOrTrunc(W));
}

ref<ConstantExpr> ConstantExpr::SExt(Width W) {
    return ConstantExpr::alloc(APInt(value).sextOrTrunc(W));
}

ref<ConstantExpr> ConstantExpr::Add(const ref<ConstantExpr> &RHS) {
    return ConstantExpr::alloc(value + RHS->value);
}

ref<ConstantExpr> ConstantExpr::Neg() {
    return ConstantExpr::alloc(-value);
}

ref<ConstantExpr> ConstantExpr::Sub(const ref<ConstantExpr> &RHS) {
    return ConstantExpr::alloc(value - RHS->value);
}

ref<ConstantExpr> ConstantExpr::Mul(const ref<ConstantExpr> &RHS) {
    return ConstantExpr::alloc(value * RHS->value);
}

ref<ConstantExpr> ConstantExpr::UDiv(const ref<ConstantExpr> &RHS) {
    return ConstantExpr::alloc(value.udiv(RHS->value));
}

ref<ConstantExpr> ConstantExpr::SDiv(const ref<ConstantExpr> &RHS) {
    return ConstantExpr::alloc(value.sdiv(RHS->value));
}

ref<ConstantExpr> ConstantExpr::URem(const ref<ConstantExpr> &RHS) {
    return ConstantExpr::alloc(value.urem(RHS->value));
}

ref<ConstantExpr> ConstantExpr::SRem(const ref<ConstantExpr> &RHS) {
    return ConstantExpr::alloc(value.srem(RHS->value));
}

ref<ConstantExpr> ConstantExpr::And(const ref<ConstantExpr> &RHS) {
    return ConstantExpr::alloc(value & RHS->value);
}

ref<ConstantExpr> ConstantExpr::Or(const ref<ConstantExpr> &RHS) {
    return ConstantExpr::alloc(value | RHS->value);
}

ref<ConstantExpr> ConstantExpr::Xor(const ref<ConstantExpr> &RHS) {
    return ConstantExpr::alloc(value ^ RHS->value);
}

ref<ConstantExpr> ConstantExpr::Shl(const ref<ConstantExpr> &RHS) {
    return ConstantExpr::alloc(value.shl(RHS->value));
}

ref<ConstantExpr> ConstantExpr::LShr(const ref<ConstantExpr> &RHS) {
    return ConstantExpr::alloc(value.lshr(RHS->value));
}

ref<ConstantExpr> ConstantExpr::AShr(const ref<ConstantExpr> &RHS) {
    return ConstantExpr::alloc(value.ashr(RHS->value));
}

ref<ConstantExpr> ConstantExpr::Not() {
    return ConstantExpr::alloc(~value);
}

ref<ConstantExpr> ConstantExpr::Eq(const ref<ConstantExpr> &RHS) {
    return ConstantExpr::alloc(value == RHS->value, Expr::Bool);
}

ref<ConstantExpr> ConstantExpr::Ne(const ref<ConstantExpr> &RHS) {
    return ConstantExpr::alloc(value != RHS->value, Expr::Bool);
}

ref<ConstantExpr> ConstantExpr::Ult(const ref<ConstantExpr> &RHS) {
    return ConstantExpr::alloc(value.ult(RHS->value), Expr::Bool);
}

ref<ConstantExpr> ConstantExpr::Ule(const ref<ConstantExpr> &RHS) {
    return ConstantExpr::alloc(value.ule(RHS->value), Expr::Bool);
}

ref<ConstantExpr> ConstantExpr::Ugt(const ref<ConstantExpr> &RHS) {
    return ConstantExpr::alloc(value.ugt(RHS->value), Expr::Bool);
}

ref<ConstantExpr> ConstantExpr::Uge(const ref<ConstantExpr> &RHS) {
    return ConstantExpr::alloc(value.uge(RHS->value), Expr::Bool);
}

ref<ConstantExpr> ConstantExpr::Slt(const ref<ConstantExpr> &RHS) {
    return ConstantExpr::alloc(value.slt(RHS->value), Expr::Bool);
}

ref<ConstantExpr> ConstantExpr::Sle(const ref<ConstantExpr> &RHS) {
    return ConstantExpr::alloc(value.sle(RHS->value), Expr::Bool);
}

ref<ConstantExpr> ConstantExpr::Sgt(const ref<ConstantExpr> &RHS) {
    return ConstantExpr::alloc(value.sgt(RHS->value), Expr::Bool);
}

ref<ConstantExpr> ConstantExpr::Sge(const ref<ConstantExpr> &RHS) {
    return ConstantExpr::alloc(value.sge(RHS->value), Expr::Bool);
}

/***/

Array::~Array() {
    // FIXME: This shouldn't be necessary.
    aggregatedSize -= size;
}

/***/

// XXX: The following optimizations seem to make things worse
#if 0
#define __LIFT_CONST_SELECT_1(e1, ...)                                                          \
    if (const SelectExpr *se = dyn_cast<SelectExpr>(e1))                                        \
        if (se->hasConstantCases())                                                             \
            return SelectExpr::create(se->getCondition(), create(se->getTrue(), ##__VA_ARGS__), \
                                      create(se->getFalse(), ##__VA_ARGS__));

#define __LIFT_CONST_SELECT_2(e1, e2, ...)                                                                          \
    if (const SelectExpr *se = dyn_cast<SelectExpr>(e1)) {                                                          \
        if (const SelectExpr *se2 = dyn_cast<SelectExpr>(e2))                                                       \
            if (se->getCondition() == se2 > getCondition())                                                         \
                return SelectExpr::create(se->getCondition(), create(se->getTrue(), se2->getTrue(), ##__VA_ARGS__), \
                                          create(se->getFalse(), se2->getFalse(), ##__VA_ARGS__));                  \
        if (se->hasConstantCases())                                                                                 \
            return SelectExpr::create(se->getCondition(), create(se->getTrue(), e2, ##__VA_ARGS__),                 \
                                      create(se->getFalse(), e2, ##__VA_ARGS__));                                   \
    }                                                                                                               \
    if (const SelectExpr *se = dyn_cast<SelectExpr>(e2))                                                            \
        if (se->hasConstantCases())                                                                                 \
            return SelectExpr::create(se->getCondition(), create(e1, se->getTrue(), ##__VA_ARGS__),                 \
                                      create(e1, se->getFalse(), ##__VA_ARGS__));

#else
#define __LIFT_CONST_SELECT_1(e1, ...)
#define __LIFT_CONST_SELECT_2(e1, e2, ...)
#endif

/***/

ref<Expr> ReadExpr::create(const UpdateListPtr &ul, ref<Expr> index) {
    if (const SelectExpr *se = dyn_cast<SelectExpr>(index))
        if (se->hasConstantCases())
            return SelectExpr::create(se->getCondition(), ReadExpr::create(ul, se->getTrue()),
                                      ReadExpr::create(ul, se->getFalse()));

    // rollback index when possible...

    // XXX this doesn't really belong here... there are basically two
    // cases, one is rebuild, where we want to optimistically try various
    // optimizations when the index has changed, and the other is
    // initial creation, where we expect the ObjectState to have constructed
    // a smart UpdateList so it is not worth rescanning.

    auto un = ul->head;
    for (; un; un = un->getNext()) {
        ref<Expr> cond = EqExpr::create(index, un->getIndex());

        if (ConstantExpr *CE = dyn_cast<ConstantExpr>(cond)) {
            if (CE->isTrue())
                return un->getValue();
        } else {
            break;
        }
    }

    return ReadExpr::alloc(ul, index);
}

ref<Expr> ReadExpr::createTempRead(const ArrayPtr &array, Expr::Width w) {
    auto ul = UpdateList::create(array, 0);

    switch (w) {
        default:
            pabort("invalid width");
        case Expr::Bool:
            return ZExtExpr::create(ReadExpr::create(ul, ConstantExpr::alloc(0, Expr::Int32)), Expr::Bool);
        case Expr::Int8:
            return ReadExpr::create(ul, ConstantExpr::alloc(0, Expr::Int32));
        case Expr::Int16:
            return ConcatExpr::create(ReadExpr::create(ul, ConstantExpr::alloc(1, Expr::Int32)),
                                      ReadExpr::create(ul, ConstantExpr::alloc(0, Expr::Int32)));
        case Expr::Int32:
            return ConcatExpr::create4(ReadExpr::create(ul, ConstantExpr::alloc(3, Expr::Int32)),
                                       ReadExpr::create(ul, ConstantExpr::alloc(2, Expr::Int32)),
                                       ReadExpr::create(ul, ConstantExpr::alloc(1, Expr::Int32)),
                                       ReadExpr::create(ul, ConstantExpr::alloc(0, Expr::Int32)));
        case Expr::Int64:
            return ConcatExpr::create8(ReadExpr::create(ul, ConstantExpr::alloc(7, Expr::Int32)),
                                       ReadExpr::create(ul, ConstantExpr::alloc(6, Expr::Int32)),
                                       ReadExpr::create(ul, ConstantExpr::alloc(5, Expr::Int32)),
                                       ReadExpr::create(ul, ConstantExpr::alloc(4, Expr::Int32)),
                                       ReadExpr::create(ul, ConstantExpr::alloc(3, Expr::Int32)),
                                       ReadExpr::create(ul, ConstantExpr::alloc(2, Expr::Int32)),
                                       ReadExpr::create(ul, ConstantExpr::alloc(1, Expr::Int32)),
                                       ReadExpr::create(ul, ConstantExpr::alloc(0, Expr::Int32)));
    }
}

int ReadExpr::compareContents(const Expr &b) const {
    return updates->compare(static_cast<const ReadExpr &>(b).updates);
}

ref<Expr> SelectExpr::create(const ref<Expr> &c, const ref<Expr> &t, const ref<Expr> &f) {
    Expr::Width kt = t->getWidth();

    assert(c->getWidth() == Bool && "type mismatch");
    assert(kt == f->getWidth() && "type mismatch");

    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(c)) {
        return CE->isTrue() ? t : f;
    } else if (t == f) {
        return t;
    } else if (SelectExpr *se = dyn_cast<SelectExpr>(t)) {
        if (f == se->getFalse())
            return SelectExpr::create(AndExpr::create(c, se->getCondition()), se->getTrue(), f);
        else if (f == se->getTrue())
            return SelectExpr::create(AndExpr::create(c, NotExpr::create(se->getCondition())), se->getFalse(), f);
    } else if (SelectExpr *se = dyn_cast<SelectExpr>(f)) {
        if (t == se->getTrue())
            return SelectExpr::create(OrExpr::create(c, se->getCondition()), t, se->getFalse());
        else if (t == se->getFalse())
            return SelectExpr::create(OrExpr::create(c, NotExpr::create(se->getCondition())), t, se->getTrue());
    } else if (kt == Expr::Bool) { // c ? t : f  <=> (c and t) or (not c and f)
        if (ConstantExpr *CE = dyn_cast<ConstantExpr>(t)) {
            if (CE->isTrue()) {
                return OrExpr::create(c, f);
            } else {
                return AndExpr::create(Expr::createIsZero(c), f);
            }
        } else if (ConstantExpr *CE = dyn_cast<ConstantExpr>(f)) {
            if (CE->isTrue()) {
                return OrExpr::create(Expr::createIsZero(c), t);
            } else {
                return AndExpr::create(c, t);
            }
        }
    }

    return SelectExpr::alloc(c, t, f);
}

/***/

ref<Expr> ConcatExpr::create(const ref<Expr> &l, const ref<Expr> &r) {
    Expr::Width w = l->getWidth() + r->getWidth();

    // Fold concatenation of constants.
    //
    if (ConstantExpr *lCE = dyn_cast<ConstantExpr>(l)) {
        if (ConstantExpr *rCE = dyn_cast<ConstantExpr>(r))
            return lCE->Concat(rCE);
        // concat 0 x -> zext x
        if (lCE->isZero()) {
            return ZExtExpr::create(r, w);
        }
    }

    // Merge contiguous Extracts
    if (ExtractExpr *ee_left = dyn_cast<ExtractExpr>(l)) {
        if (ExtractExpr *ee_right = dyn_cast<ExtractExpr>(r)) {
            if (ee_left->getExpr() == ee_right->getExpr() &&
                ee_right->getOffset() + ee_right->getWidth() == ee_left->getOffset()) {
                return ExtractExpr::create(ee_left->getExpr(), ee_right->getOffset(), w);
            }
        }
    }

    __LIFT_CONST_SELECT_2(l, r);

    return ConcatExpr::alloc(l, r);
}

/// Shortcut to concat N kids.  The chain returned is unbalanced to the right
ref<Expr> ConcatExpr::createN(unsigned n_kids, const ref<Expr> kids[]) {
    assert(n_kids > 0);
    if (n_kids == 1)
        return kids[0];

    ref<Expr> r = ConcatExpr::create(kids[n_kids - 2], kids[n_kids - 1]);
    for (int i = n_kids - 3; i >= 0; i--)
        r = ConcatExpr::create(kids[i], r);
    return r;
}

/// Shortcut to concat 4 kids.  The chain returned is unbalanced to the right
ref<Expr> ConcatExpr::create4(const ref<Expr> &kid1, const ref<Expr> &kid2, const ref<Expr> &kid3,
                              const ref<Expr> &kid4) {
    return ConcatExpr::create(kid1, ConcatExpr::create(kid2, ConcatExpr::create(kid3, kid4)));
}

/// Shortcut to concat 8 kids.  The chain returned is unbalanced to the right
ref<Expr> ConcatExpr::create8(const ref<Expr> &kid1, const ref<Expr> &kid2, const ref<Expr> &kid3,
                              const ref<Expr> &kid4, const ref<Expr> &kid5, const ref<Expr> &kid6,
                              const ref<Expr> &kid7, const ref<Expr> &kid8) {
    return ConcatExpr::create(
        kid1,
        ConcatExpr::create(
            kid2, ConcatExpr::create(kid3, ConcatExpr::create(kid4, ConcatExpr::create4(kid5, kid6, kid7, kid8)))));
}

/***/

ref<Expr> ExtractExpr::create(const ref<Expr> &expr, unsigned off, Width w) {
    unsigned kw = expr->getWidth();
    assert(w > 0 && off + w <= kw && "invalid extract");

    if (w == kw) {
        return expr;
    }

    else if (ConstantExpr *CE = dyn_cast<ConstantExpr>(expr)) {
        return CE->Extract(off, w);
    }

    // simplify E(Zext(x)) = x
    else if (ZExtExpr *ze = dyn_cast<ZExtExpr>(expr)) {
        // Convenience variables
        ref<Expr> x = ze->getKid(0);
        Width xw = x->getWidth();
        Width zew = ze->getWidth();
        Width ew = w;

        if (xw == w && off == 0) {
            return x;
        }
        if (ew <= zew && ew >= xw && off == 0) {
            return ZExtExpr::create(x, ew);
        }
    }

    // Extract(Concat)
    else if (ConcatExpr *ce = dyn_cast<ConcatExpr>(expr)) {
        // if the extract skips the right side of the concat
        if (off >= ce->getRight()->getWidth()) {
            return ExtractExpr::create(ce->getLeft(), off - ce->getRight()->getWidth(), w);
        }

        // if the extract skips the left side of the concat
        if (off + w <= ce->getRight()->getWidth()) {
            return ExtractExpr::create(ce->getRight(), off, w);
        }

        // E(C(x,y)) = C(E(x), E(y))
        return ConcatExpr::create(ExtractExpr::create(ce->getKid(0), 0, w - ce->getKid(1)->getWidth() + off),
                                  ExtractExpr::create(ce->getKid(1), off, ce->getKid(1)->getWidth() - off));
    }

    else if (SExtExpr *se = dyn_cast<SExtExpr>(expr)) {
        ref<Expr> x = se->getKid(0);
        Width xw = x->getWidth();

        if (off == 0 && w == Int8 && xw == Int8) {
            // Extract w8 0 (SExt w32 (xxx w8))
            return x;
        } else if (off == 0) {
            // Extract(SExt)
            return SExtExpr::create(se->getSrc(), w);
        }
    }

    // Extract(ZExt)
    else if (ZExtExpr *ze = dyn_cast<ZExtExpr>(expr)) {
        if (off == 0) {
            return ZExtExpr::create(ze->getSrc(), w);
        }

        if (off >= ze->getSrc()->getWidth()) {
            return ConstantExpr::alloc(0, w);
        }
    }

    __LIFT_CONST_SELECT_1(expr, off, w);

    auto ret = ExtractExpr::alloc(expr, off, w);
    auto ret1 = SimplifyExtractAndZext(ret);
    return SimplifyExtractLShr(ret1);
}

/***/

ref<Expr> NotExpr::create(const ref<Expr> &e) {
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(e))
        return CE->Not();

    __LIFT_CONST_SELECT_1(e);

    return NotExpr::alloc(e);
}

/***/

ref<Expr> ZExtExpr::create(const ref<Expr> &e, Width w) {
    unsigned kBits = e->getWidth();
    if (w == kBits) {
        return e;
    } else if (w < kBits) { // trunc
        return ExtractExpr::create(e, 0, w);
    } else if (ConstantExpr *CE = dyn_cast<ConstantExpr>(e)) {
        return CE->ZExt(w);
    } else if (ZExtExpr *ZE = dyn_cast<ZExtExpr>(e)) {
        if (ZE->getWidth() < w) {
            return ZExtExpr::alloc(ZE->getKid(0), w);
        } else {
            return ZExtExpr::alloc(e, w);
        }
    } else {
        __LIFT_CONST_SELECT_1(e, w);
        return ZExtExpr::alloc(e, w);
    }
}

ref<Expr> SExtExpr::create(const ref<Expr> &e, Width w) {
    unsigned kBits = e->getWidth();
    if (w == kBits) {
        return e;
    } else if (w < kBits) { // trunc
        return ExtractExpr::create(e, 0, w);
    } else if (ConstantExpr *CE = dyn_cast<ConstantExpr>(e)) {
        return CE->SExt(w);
    } else {
        __LIFT_CONST_SELECT_1(e, w);
        return SExtExpr::alloc(e, w);
    }
}

/***/

static ref<Expr> AndExpr_create(Expr *l, Expr *r);
static ref<Expr> XorExpr_create(Expr *l, Expr *r);

static ref<Expr> EqExpr_createPartial(Expr *l, const ref<ConstantExpr> &cr);
static ref<Expr> AndExpr_createPartialR(const ref<ConstantExpr> &cl, Expr *r);
static ref<Expr> SubExpr_createPartialR(const ref<ConstantExpr> &cl, Expr *r);
static ref<Expr> XorExpr_createPartialR(const ref<ConstantExpr> &cl, Expr *r);

static ref<Expr> AddExpr_createPartialR(const ref<ConstantExpr> &cl, Expr *r) {
    Expr::Width type = cl->getWidth();

    if (type == Expr::Bool) {
        return XorExpr_createPartialR(cl, r);
    } else if (cl->isZero()) {
        return r;
    } else {
        Expr::Kind rk = r->getKind();
        if (rk == Expr::Add && isa<ConstantExpr>(r->getKid(0))) { // A + (B+c) == (A+B) + c
            return AddExpr::create(AddExpr::create(cl, r->getKid(0)), r->getKid(1));
        } else if (rk == Expr::Sub && isa<ConstantExpr>(r->getKid(0))) { // A + (B-c) == (A+B) - c
            return SubExpr::create(AddExpr::create(cl, r->getKid(0)), r->getKid(1));
        } else {
            return AddExpr::alloc(cl, r);
        }
    }
}
static ref<Expr> AddExpr_createPartial(Expr *l, const ref<ConstantExpr> &cr) {
    return AddExpr_createPartialR(cr, l);
}
static ref<Expr> AddExpr_create(Expr *l, Expr *r) {
    Expr::Width type = l->getWidth();

    if (type == Expr::Bool) {
        return XorExpr_create(l, r);
    } else {
        Expr::Kind lk = l->getKind(), rk = r->getKind();
        if (lk == Expr::Add && isa<ConstantExpr>(l->getKid(0))) { // (k+a)+b = k+(a+b)
            return AddExpr::create(l->getKid(0), AddExpr::create(l->getKid(1), r));
        } else if (lk == Expr::Sub && isa<ConstantExpr>(l->getKid(0))) { // (k-a)+b = k+(b-a)
            return AddExpr::create(l->getKid(0), SubExpr::create(r, l->getKid(1)));
        } else if (rk == Expr::Add && isa<ConstantExpr>(r->getKid(0))) { // a + (k+b) = k+(a+b)
            return AddExpr::create(r->getKid(0), AddExpr::create(l, r->getKid(1)));
        } else if (rk == Expr::Sub && isa<ConstantExpr>(r->getKid(0))) { // a + (k-b) = k+(a-b)
            return AddExpr::create(r->getKid(0), SubExpr::create(l, r->getKid(1)));
        } else {
            return AddExpr::alloc(l, r);
        }
    }
}

static ref<Expr> SubExpr_createPartialR(const ref<ConstantExpr> &cl, Expr *r) {
    Expr::Width type = cl->getWidth();

    if (type == Expr::Bool) {
        return XorExpr_createPartialR(cl, r);
    } else {
        Expr::Kind rk = r->getKind();
        if (rk == Expr::Add && isa<ConstantExpr>(r->getKid(0))) { // A - (B+c) == (A-B) - c
            return SubExpr::create(SubExpr::create(cl, r->getKid(0)), r->getKid(1));
        } else if (rk == Expr::Sub && isa<ConstantExpr>(r->getKid(0))) { // A - (B-c) == (A-B) + c
            return AddExpr::create(SubExpr::create(cl, r->getKid(0)), r->getKid(1));
        } else {
            return SubExpr::alloc(cl, r);
        }
    }
}
static ref<Expr> SubExpr_createPartial(Expr *l, const ref<ConstantExpr> &cr) {
    // l - c => l + (-c)
    return AddExpr_createPartial(l, ConstantExpr::alloc(0, cr->getWidth())->Sub(cr));
}
static ref<Expr> SubExpr_create(Expr *l, Expr *r) {
    Expr::Width type = l->getWidth();

    if (type == Expr::Bool) {
        return XorExpr_create(l, r);
    } else if (*l == *r) {
        return ConstantExpr::alloc(0, type);
    } else {
        Expr::Kind lk = l->getKind(), rk = r->getKind();
        if (lk == Expr::Add && isa<ConstantExpr>(l->getKid(0))) { // (k+a)-b = k+(a-b)
            return AddExpr::create(l->getKid(0), SubExpr::create(l->getKid(1), r));
        } else if (lk == Expr::Sub && isa<ConstantExpr>(l->getKid(0))) { // (k-a)-b = k-(a+b)
            return SubExpr::create(l->getKid(0), AddExpr::create(l->getKid(1), r));
        } else if (rk == Expr::Add && isa<ConstantExpr>(r->getKid(0))) { // a - (k+b) = (a-c) - k
            return SubExpr::create(SubExpr::create(l, r->getKid(1)), r->getKid(0));
        } else if (rk == Expr::Sub && isa<ConstantExpr>(r->getKid(0))) { // a - (k-b) = (a+b) - k
            return SubExpr::create(AddExpr::create(l, r->getKid(1)), r->getKid(0));
        } else {
            return SubExpr::alloc(l, r);
        }
    }
}

static ref<Expr> MulExpr_createPartialR(const ref<ConstantExpr> &cl, Expr *r) {
    Expr::Width type = cl->getWidth();

    if (type == Expr::Bool) {
        return AndExpr_createPartialR(cl, r);
    } else if (cl->isOne()) {
        return r;
    } else if (cl->isZero()) {
        return cl;
    } else {
        return MulExpr::alloc(cl, r);
    }
}
static ref<Expr> MulExpr_createPartial(Expr *l, const ref<ConstantExpr> &cr) {
    return MulExpr_createPartialR(cr, l);
}
static ref<Expr> MulExpr_create(Expr *l, Expr *r) {
    Expr::Width type = l->getWidth();

    if (type == Expr::Bool) {
        return AndExpr::alloc(l, r);
    } else {
        return MulExpr::alloc(l, r);
    }
}

static ref<Expr> AndExpr_createPartial(Expr *l, const ref<ConstantExpr> &cr) {
    if (cr->isAllOnes()) {
        return l;
    } else if (cr->isZero()) {
        return cr;
    } else if (OrExpr *ol = dyn_cast<OrExpr>(l)) {
        // b and c are const =>
        // (a or b) and c => (a and c) or (b and c) => (a and c) or const
        // This is useful in case (b and c) evaluate to 0.
        const ref<ConstantExpr> &c = cr;
        const ref<Expr> a = ol->getKid(0);
        const ref<ConstantExpr> b = dyn_cast<ConstantExpr>(ol->getKid(1));
        if (!b.isNull() && !(c->getZExtValue() & b->getZExtValue())) {
            return AndExpr::create(a, c);
        }
    } else if (AndExpr *al = dyn_cast<AndExpr>(l)) {
        // (a and const 1) and const2 => a and (const1 and const2)
        const ref<Expr> a = al->getKid(0);
        const ref<ConstantExpr> c1 = cr;
        const ref<ConstantExpr> c2 = dyn_cast<ConstantExpr>(al->getKid(1));
        if (!c2.isNull()) {
            return AndExpr::create(a, AndExpr::create(c1, c2));
        }
    }

    return AndExpr::alloc(l, cr);
}

static ref<Expr> AndExpr_createPartialR(const ref<ConstantExpr> &cl, Expr *r) {
    return AndExpr_createPartial(r, cl);
}

static ref<Expr> AndExpr_create(Expr *l, Expr *r) {
    if (l->isNegationOf(r))
        return ConstantExpr::create(0, Expr::Bool);
    if (OrExpr *ae = dyn_cast<OrExpr>(l)) {
        // (!r || b) && r == b && r
        if (ae->getLeft()->isNegationOf(r))
            return AndExpr::create(ae->getRight(), r);
        if (ae->getRight()->isNegationOf(r))
            return AndExpr::create(ae->getLeft(), r);
    }
    if (OrExpr *ae = dyn_cast<OrExpr>(r)) {
        // l && (!l || b) == l && b
        if (ae->getLeft()->isNegationOf(l))
            return AndExpr::create(l, ae->getRight());
        if (ae->getRight()->isNegationOf(l))
            return AndExpr::create(l, ae->getLeft());
    }
    return AndExpr::alloc(l, r);
}

static ref<Expr> OrExpr_createPartial(Expr *l, const ref<ConstantExpr> &cr) {
    if (cr->isAllOnes()) {
        return cr;
    } else if (cr->isZero()) {
        return l;
    } else if (const OrExpr *ol = dyn_cast<OrExpr>(l)) {
        // Compact or(or(a, const1), const2) => or(a, const1 | const2)
        ref<ConstantExpr> const2 = dyn_cast<ConstantExpr>(ol->getKid(1));
        if (!const2.isNull()) {
            return OrExpr::create(ol->getKid(0), OrExpr::create(cr, const2));
        }
        return OrExpr::alloc(l, cr);
    } else {
        return OrExpr::alloc(l, cr);
    }
}

static ref<Expr> OrExpr_createPartialR(const ref<ConstantExpr> &cl, Expr *r) {
    return OrExpr_createPartial(r, cl);
}

static ref<Expr> OrExpr_create(Expr *l, Expr *r) {
    if (l->isNegationOf(r))
        return ConstantExpr::create(1, Expr::Bool);
    /*
  if (EqExpr *e = dyn_cast<EqExpr>(l)) {
    if (e->getLeft()->isZero() && *r == *e->getRight()) {
      return ConstantExpr::create(1, Expr::Bool);
    }
  }
  if (EqExpr *e = dyn_cast<EqExpr>(r)) {
    if (e->getLeft()->isZero() && *l == *e->getRight()) {
      return ConstantExpr::create(1, Expr::Bool);
    }
  }*/
    if (AndExpr *ae = dyn_cast<AndExpr>(l)) {
        // (!r && b) || r == b || r
        if (ae->getLeft()->isNegationOf(r))
            return OrExpr::create(ae->getRight(), r);
        if (ae->getRight()->isNegationOf(r))
            return OrExpr::create(ae->getLeft(), r);
    }
    if (AndExpr *ae = dyn_cast<AndExpr>(r)) {
        // l || (!l && b) == l || b
        if (ae->getLeft()->isNegationOf(l))
            return OrExpr::create(l, ae->getRight());
        if (ae->getRight()->isNegationOf(l))
            return OrExpr::create(l, ae->getLeft());
    }
    auto ret = OrExpr::alloc(l, r);
    return SimplifyUnalignedReadPattern(ret);
}

static ref<Expr> XorExpr_createPartialR(const ref<ConstantExpr> &cl, Expr *r) {
    if (cl->isZero()) {
        return r;
    } else if (cl->getWidth() == Expr::Bool) {
        return EqExpr_createPartial(r, ConstantExpr::create(0, Expr::Bool));
    } else {
        return XorExpr::alloc(cl, r);
    }
}

static ref<Expr> XorExpr_createPartial(Expr *l, const ref<ConstantExpr> &cr) {
    return XorExpr_createPartialR(cr, l);
}
static ref<Expr> XorExpr_create(Expr *l, Expr *r) {
    if (l == r)
        return ConstantExpr::alloc(0, l->getWidth());
    if (l->isNegationOf(r))
        return ConstantExpr::alloc(1, Expr::Bool);
    return XorExpr::alloc(l, r);
}

static ref<Expr> UDivExpr_create(const ref<Expr> &l, const ref<Expr> &r) {
    if (l->getWidth() == Expr::Bool) { // r must be 1
        return l;
    } else {
        return UDivExpr::alloc(l, r);
    }
}

static ref<Expr> SDivExpr_create(const ref<Expr> &l, const ref<Expr> &r) {
    if (l->getWidth() == Expr::Bool) { // r must be 1
        return l;
    } else {
        return SDivExpr::alloc(l, r);
    }
}

static ref<Expr> URemExpr_create(const ref<Expr> &l, const ref<Expr> &r) {
    if (l->getWidth() == Expr::Bool) { // r must be 1
        return ConstantExpr::create(0, Expr::Bool);
    } else {
        return URemExpr::alloc(l, r);
    }
}

static ref<Expr> SRemExpr_create(const ref<Expr> &l, const ref<Expr> &r) {
    if (l->getWidth() == Expr::Bool) { // r must be 1
        return ConstantExpr::create(0, Expr::Bool);
    } else {
        return SRemExpr::alloc(l, r);
    }
}

static ref<Expr> ShlExpr_create(const ref<Expr> &l, const ref<Expr> &r) {
    if (l->getWidth() == Expr::Bool) { // l & !r
        return AndExpr::create(l, Expr::createIsZero(r));
    } else {
        // Shifting by 0 is a no-op
        ConstantExpr *ce = dyn_cast<ConstantExpr>(r);
        if (ce && ce->getZExtValue() == 0) {
            return l;
        }
        return ShlExpr::alloc(l, r);
    }
}

static ref<Expr> LShrExpr_create(const ref<Expr> &l, const ref<Expr> &r) {
    if (l->getWidth() == Expr::Bool) { // l & !r
        return AndExpr::create(l, Expr::createIsZero(r));
    } else {
        return LShrExpr::alloc(l, r);
    }
}

static ref<Expr> AShrExpr_create(const ref<Expr> &l, const ref<Expr> &r) {
    if (l->getWidth() == Expr::Bool) { // l
        return l;
    } else {
        return AShrExpr::alloc(l, r);
    }
}

#define BCREATE_R(_e_op, _op, partialL, partialR)                     \
    ref<Expr> _e_op::create(const ref<Expr> &l, const ref<Expr> &r) { \
        assert(l->getWidth() == r->getWidth() && "type mismatch");    \
        if (ConstantExpr *cl = dyn_cast<ConstantExpr>(l)) {           \
            if (ConstantExpr *cr = dyn_cast<ConstantExpr>(r))         \
                return cl->_op(cr);                                   \
            __LIFT_CONST_SELECT_2(l, r);                              \
            return _e_op##_createPartialR(cl, r.get());               \
        } else if (ConstantExpr *cr = dyn_cast<ConstantExpr>(r)) {    \
            __LIFT_CONST_SELECT_1(l, r);                              \
            return _e_op##_createPartial(l.get(), cr);                \
        }                                                             \
        __LIFT_CONST_SELECT_2(l, r);                                  \
        return _e_op##_create(l.get(), r.get());                      \
    }

#if 1

#define BCREATE(_e_op, _op)                                           \
    ref<Expr> _e_op::create(const ref<Expr> &l, const ref<Expr> &r) { \
        assert(l->getWidth() == r->getWidth() && "type mismatch");    \
        if (ConstantExpr *cl = dyn_cast<ConstantExpr>(l))             \
            if (ConstantExpr *cr = dyn_cast<ConstantExpr>(r))         \
                return cl->_op(cr);                                   \
        __LIFT_CONST_SELECT_2(l, r);                                  \
        return _e_op##_create(l, r);                                  \
    }
#else

#define BCREATE(_e_op, _op)                                           \
    ref<Expr> _e_op::create(const ref<Expr> &l, const ref<Expr> &r) { \
        assert(l->getWidth() == r->getWidth() && "type mismatch");    \
        if (ConstantExpr *cl = dyn_cast<ConstantExpr>(l))             \
            if (ConstantExpr *cr = dyn_cast<ConstantExpr>(r))         \
                return cl->_op(cr);                                   \
        return _e_op##_create(l, r);                                  \
    }

#endif

BCREATE_R(AddExpr, Add, AddExpr_createPartial, AddExpr_createPartialR)
BCREATE_R(SubExpr, Sub, SubExpr_createPartial, SubExpr_createPartialR)
BCREATE_R(MulExpr, Mul, MulExpr_createPartial, MulExpr_createPartialR)
BCREATE_R(AndExpr, And, AndExpr_createPartial, AndExpr_createPartialR)
BCREATE_R(OrExpr, Or, OrExpr_createPartial, OrExpr_createPartialR)
BCREATE_R(XorExpr, Xor, XorExpr_createPartial, XorExpr_createPartialR)
BCREATE(UDivExpr, UDiv)
BCREATE(SDivExpr, SDiv)
BCREATE(URemExpr, URem)
BCREATE(SRemExpr, SRem)
BCREATE(ShlExpr, Shl)
BCREATE(LShrExpr, LShr)
BCREATE(AShrExpr, AShr)

#if 0
#define CMPCREATE(_e_op, _op)                                         \
    ref<Expr> _e_op::create(const ref<Expr> &l, const ref<Expr> &r) { \
        assert(l->getWidth() == r->getWidth() && "type mismatch");    \
        if (ConstantExpr *cl = dyn_cast<ConstantExpr>(l))             \
            if (ConstantExpr *cr = dyn_cast<ConstantExpr>(r))         \
                return cl->_op(cr);                                   \
//__LIFT_CONST_SELECT_2(l, r);                                          \
return _e_op ## _create(l, r);                                        \
}
#endif

#define CMPCREATE(_e_op, _op)                                         \
    ref<Expr> _e_op::create(const ref<Expr> &l, const ref<Expr> &r) { \
        assert(l->getWidth() == r->getWidth() && "type mismatch");    \
        if (ConstantExpr *cl = dyn_cast<ConstantExpr>(l))             \
            if (ConstantExpr *cr = dyn_cast<ConstantExpr>(r))         \
                return cl->_op(cr);                                   \
        return _e_op##_create(l, r);                                  \
    }

#if 0
#define CMPCREATE_T(_e_op, _op, _reflexive_e_op, partialL, partialR)  \
    ref<Expr> _e_op::create(const ref<Expr> &l, const ref<Expr> &r) { \
        assert(l->getWidth() == r->getWidth() && "type mismatch");    \
//__LIFT_CONST_SELECT_2(l, r);                                         \
if (ConstantExpr *cl = dyn_cast<ConstantExpr>(l)) {                  \
    if (ConstantExpr *cr = dyn_cast<ConstantExpr>(r))                  \
        return cl->_op(cr);                                              \
    return partialR(cl, r.get());                                      \
} else if (ConstantExpr *cr = dyn_cast<ConstantExpr>(r)) {           \
    return partialL(l.get(), cr);                                      \
} else {                                                             \
return _e_op ## _create(l.get(), r.get());                         \
}                                                                    \
}
#endif
#define CMPCREATE_T(_e_op, _op, _reflexive_e_op, partialL, partialR)  \
    ref<Expr> _e_op::create(const ref<Expr> &l, const ref<Expr> &r) { \
        assert(l->getWidth() == r->getWidth() && "type mismatch");    \
        if (ConstantExpr *cl = dyn_cast<ConstantExpr>(l)) {           \
            if (ConstantExpr *cr = dyn_cast<ConstantExpr>(r))         \
                return cl->_op(cr);                                   \
            return partialR(cl, r.get());                             \
        } else if (ConstantExpr *cr = dyn_cast<ConstantExpr>(r)) {    \
            return partialL(l.get(), cr);                             \
        } else {                                                      \
            return _e_op##_create(l.get(), r.get());                  \
        }                                                             \
    }

static ref<Expr> EqExpr_create(const ref<Expr> &l, const ref<Expr> &r) {
    if (l == r) {
        return ConstantExpr::alloc(1, Expr::Bool);
    } else {
        return EqExpr::alloc(l, r);
    }
}

/// Tries to optimize EqExpr cl == rd, where cl is a ConstantExpr and
/// rd a ReadExpr.  If rd is a read into an all-constant array,
/// returns a disjunction of equalities on the index.  Otherwise,
/// returns the initial equality expression.
static ref<Expr> TryConstArrayOpt(const ref<ConstantExpr> &cl, ReadExpr *rd) {
    if (rd->getUpdates()->getRoot()->isSymbolicArray() || rd->getUpdates()->getSize())
        return EqExpr_create(cl, rd);

    // Number of positions in the array that contain value ct.
    unsigned numMatches = 0;

    // for now, just assume standard "flushing" of a concrete array,
    // where the concrete array has one update for each index, in order
    ref<Expr> res = ConstantExpr::alloc(0, Expr::Bool);
    for (unsigned i = 0, e = rd->getUpdates()->getRoot()->getSize(); i != e; ++i) {
        if (cl == rd->getUpdates()->getRoot()->getConstantValues()[i]) {
            // Arbitrary maximum on the size of disjunction.
            if (++numMatches > 100)
                return EqExpr_create(cl, rd);

            ref<Expr> mayBe = EqExpr::create(rd->getIndex(), ConstantExpr::alloc(i, rd->getIndex()->getWidth()));
            res = OrExpr::create(res, mayBe);
        }
    }

    return res;
}

static ref<Expr> EqExpr_createPartialR(const ref<ConstantExpr> &cl, Expr *r) {
    Expr::Width width = cl->getWidth();

    Expr::Kind rk = r->getKind();
    if (width == Expr::Bool) {
        if (cl->isTrue()) {
            return r;
        } else {
            // 0 == ...

            if (rk == Expr::Eq) {
                const EqExpr *ree = cast<EqExpr>(r);

                // eliminate double negation
                if (ConstantExpr *CE = dyn_cast<ConstantExpr>(ree->getLeft())) {
                    // 0 == (0 == A) => A
                    if (CE->getWidth() == Expr::Bool && CE->isFalse())
                        return ree->getRight();
                }
            } else if (rk == Expr::Or) {
                const OrExpr *roe = cast<OrExpr>(r);

                // transform not(or(a,b)) to and(not a, not b)
                return AndExpr::create(Expr::createIsZero(roe->getLeft()), Expr::createIsZero(roe->getRight()));
            }
        }
    } else if (rk == Expr::SExt) {
        // (sext(a,T)==c) == (a==c)
        const SExtExpr *see = cast<SExtExpr>(r);
        Expr::Width fromBits = see->getSrc()->getWidth();
        ref<ConstantExpr> trunc = cl->ZExt(fromBits);

        // pathological check, make sure it is possible to
        // sext to this value *from any value*
        if (cl == trunc->SExt(width)) {
            return EqExpr::create(see->getSrc(), trunc);
        } else {
            return ConstantExpr::create(0, Expr::Bool);
        }
    } else if (rk == Expr::ZExt) {
        // (zext(a,T)==c) == (a==c)
        const ZExtExpr *zee = cast<ZExtExpr>(r);
        Expr::Width fromBits = zee->getSrc()->getWidth();
        ref<ConstantExpr> trunc = cl->ZExt(fromBits);

        // pathological check, make sure it is possible to
        // zext to this value *from any value*
        if (cl == trunc->ZExt(width)) {
            return EqExpr::create(zee->getSrc(), trunc);
        } else {
            return ConstantExpr::create(0, Expr::Bool);
        }
    } else if (rk == Expr::Add) {
        const AddExpr *ae = cast<AddExpr>(r);
        if (isa<ConstantExpr>(ae->getLeft())) {
            // c0 = c1 + b => c0 - c1 = b
            return EqExpr_createPartialR(cast<ConstantExpr>(SubExpr::create(cl, ae->getLeft())), ae->getRight().get());
        }
    } else if (rk == Expr::Sub) {
        const SubExpr *se = cast<SubExpr>(r);
        if (isa<ConstantExpr>(se->getLeft())) {
            // c0 = c1 - b => c1 - c0 = b
            return EqExpr_createPartialR(cast<ConstantExpr>(SubExpr::create(se->getLeft(), cl)), se->getRight().get());
        }
    } else if (rk == Expr::Read && ConstArrayOpt) {
        return TryConstArrayOpt(cl, static_cast<ReadExpr *>(r));
    }

    return EqExpr_create(cl, r);
}

static ref<Expr> EqExpr_createPartial(Expr *l, const ref<ConstantExpr> &cr) {
    return EqExpr_createPartialR(cr, l);
}

ref<Expr> NeExpr::create(const ref<Expr> &l, const ref<Expr> &r) {
    return EqExpr::create(ConstantExpr::create(0, Expr::Bool), EqExpr::create(l, r));
}

ref<Expr> UgtExpr::create(const ref<Expr> &l, const ref<Expr> &r) {
    return UltExpr::create(r, l);
}
ref<Expr> UgeExpr::create(const ref<Expr> &l, const ref<Expr> &r) {
    return UleExpr::create(r, l);
}

ref<Expr> SgtExpr::create(const ref<Expr> &l, const ref<Expr> &r) {
    return SltExpr::create(r, l);
}
ref<Expr> SgeExpr::create(const ref<Expr> &l, const ref<Expr> &r) {
    return SleExpr::create(r, l);
}

static ref<Expr> UltExpr_create(const ref<Expr> &l, const ref<Expr> &r) {
    Expr::Width t = l->getWidth();
    if (t == Expr::Bool) { // !l && r
        return AndExpr::create(Expr::createIsZero(l), r);
    } else {
        return UltExpr::alloc(l, r);
    }
}

static ref<Expr> UleExpr_create(const ref<Expr> &l, const ref<Expr> &r) {
    if (l->getWidth() == Expr::Bool) { // !(l && !r)
        return OrExpr::create(Expr::createIsZero(l), r);
    } else {
        return UleExpr::alloc(l, r);
    }
}

static ref<Expr> SltExpr_create(const ref<Expr> &l, const ref<Expr> &r) {
    if (l->getWidth() == Expr::Bool) { // l && !r
        return AndExpr::create(l, Expr::createIsZero(r));
    } else {
        return SltExpr::alloc(l, r);
    }
}

static ref<Expr> SleExpr_create(const ref<Expr> &l, const ref<Expr> &r) {
    if (l->getWidth() == Expr::Bool) { // !(!l && r)
        return OrExpr::create(l, Expr::createIsZero(r));
    } else {
        return SleExpr::alloc(l, r);
    }
}

CMPCREATE_T(EqExpr, Eq, EqExpr, EqExpr_createPartial, EqExpr_createPartialR)
CMPCREATE(UltExpr, Ult)
CMPCREATE(UleExpr, Ule)
CMPCREATE(SltExpr, Slt)
CMPCREATE(SleExpr, Sle)

uint64_t UpdateList::count = 0;
uint64_t Array::aggregatedSize = 0;
