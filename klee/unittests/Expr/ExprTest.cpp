//===-- ExprTest.cpp ------------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include <iostream>
#include "gtest/gtest.h"

#include <klee/Expr.h>
#include <klee/Memory.h>
#include <llvm/Support/Casting.h>

using namespace klee;
using llvm::cast;
using llvm::cast_or_null;
using llvm::dyn_cast;
using llvm::dyn_cast_or_null;
using llvm::isa;

namespace {

ref<Expr> getConstant(int value, Expr::Width width) {
    int64_t ext = value;
    uint64_t trunc = ext & (((uint64_t) -1LL) >> (64 - width));
    return ConstantExpr::create(trunc, width);
}

TEST(ExprTest, BasicConstruction) {
    EXPECT_EQ(ref<Expr>(ConstantExpr::alloc(0, 32)),
              SubExpr::create(ConstantExpr::alloc(10, 32), ConstantExpr::alloc(10, 32)));
}

/// \brief create an array read expressions for the given variable names
static std::vector<ref<Expr>> GenerateLoads(const std::vector<std::string> &varNames, Expr::Width width = Expr::Int8) {
    std::vector<ref<Expr>> ret;

    for (const auto &name : varNames) {
        auto array = Array::create(name, width / 8);
        auto rd = ReadExpr::createTempRead(array, width);
        ret.push_back(rd);
    }

    return ret;
}

/// \brief Simulate an unaligned read from memory.
/// An unaligned read is a read whose start address is not a multiple of the access size.
/// Unaligned reads are broken down into two aligned reads which are then
/// shifted and merged, which results in an expression that looks like this:
///
/// (v7 v6 v5 v4) << 0x18 || (v3 v2 v1 v0) >> 0x8)
///
/// The expression above represents a read of size 4 starting from address 1.s
static ref<Expr> ReadUnalignedWord(const ObjectStatePtr &os, unsigned addr, unsigned dataSize) {
    unsigned addr1 = addr & ~(dataSize - 1);
    unsigned addr2 = addr1 + dataSize;
    unsigned shift = (addr & (dataSize - 1)) * 8;
    ref<Expr> res1 = os->read(addr1, dataSize * 8);
    if (shift == 0) {
        return res1;
    }
    ref<Expr> res2 = os->read(addr2, dataSize * 8);

    // clang-format off
    ref<Expr> res =
            OrExpr::create(
                LShrExpr::create(
                    res1, ConstantExpr::alloc(shift, dataSize * 8)
                ),
                ShlExpr::create(
                    res2, ConstantExpr::alloc((dataSize * 8) - shift, dataSize * 8)
                )
            );
    // clang-format on

    return res;
}

///
/// \brief Check that unaligned read patterns are properly simplified.
///
/// This test checks all combinations of data sizes and alignments.
///
TEST(ExprTest, UnalignedLoadSimplification1) {

    // Initialize a dummy memory object
    Context::initialize(true, Expr::Int64);
    auto os = ObjectState::allocate(0, 64, false);

    // Create symbolic variable names
    std::vector<std::string> vars;
    for (unsigned i = 0; i < 32; ++i) {
        std::stringstream ss;
        ss << "v" << i;
        vars.push_back(ss.str());
    }

    // Generate symbolic expressions and store them to memory
    auto loads = GenerateLoads(vars);
    for (unsigned i = 0; i < loads.size(); ++i) {
        os->write(i, loads[i]);
    }

    // Check 2, 4, 8-byte memory accesses
    for (unsigned i = 2; i < 16; i = i * 2) {
        // Check arbitrary alignment
        for (unsigned j = 0; j < i; ++j) {
            auto ret = ReadUnalignedWord(os, j, i);
            auto native = os->read(j, i * 8);
            EXPECT_EQ(native, ret);
        }
    }
}

static ref<Expr> GetExtractAndZExtExpr(ref<Expr> load, Expr::Width width, Expr::Width ptrWidth, uint64_t mask) {
    ref<Expr> zext = ZExtExpr::create(load, ptrWidth);
    ref<Expr> me = ConstantExpr::create(mask, ptrWidth);
    return ExtractExpr::create(AndExpr::create(zext, me), 0, width);
}

///
/// \brief Check simplification of Extract_z(0, And_x(ZExt_x(X_y), mask))
///
TEST(ExprTest, TestAndZext) {
    Expr::Width widths[] = {Expr::Int8, Expr::Int16, Expr::Int32, Expr::Int64, 0};
    uint64_t masks[] = {0xff, 0xffff, 0xffffffff, 0xffffffffffffffff};

    for (unsigned i = 0; widths[i]; ++i) {
        for (unsigned j = 0; widths[j]; ++j) {
            auto ptrWidth = widths[i];
            auto loadWidth = widths[j];
            auto mask = masks[j];

            if (ptrWidth < loadWidth) {
                continue;
            }

            std::vector<std::string> vars;
            vars.push_back("v1");
            auto loads = GenerateLoads(vars, loadWidth);
            auto ret = GetExtractAndZExtExpr(loads[0], loadWidth, ptrWidth, mask);
            EXPECT_EQ(loads[0], ret);
        }
    }
}

///
/// \brief Check transformation of ExtractN(a, LShr(b, c)) to ExtractN(b, c)
///
TEST(ExprTest, TestExtractLShr) {
    // Create symbolic variable names
    std::vector<std::string> vars;
    for (unsigned i = 0; i < 4; ++i) {
        std::stringstream ss;
        ss << "v" << i;
        vars.push_back(ss.str());
    }

    // Generate symbolic expressions and store them to memory
    auto loads = GenerateLoads(vars);

    for (unsigned i = 0; i < loads.size(); ++i) {
        auto e = ConcatExpr::createN(loads.size(), &loads[0]);
        e = LShrExpr::create(e, ConstantExpr::alloc(i * 8, Expr::Int32));
        e = ExtractExpr::create(e, 0, Expr::Int8);
        EXPECT_EQ(loads[loads.size() - 1 - i], e);
    }
}

TEST(ExprTest, ConcatExtract) {
    auto array = Array::create("arr0", 256);
    ref<Expr> read8 = ReadExpr::createTempRead(array, 8);
    auto array2 = Array::create("arr1", 256);
    ref<Expr> read8_2 = ReadExpr::createTempRead(array2, 8);
    ref<Expr> c100 = getConstant(100, 8);

    ref<Expr> concat1 = ConcatExpr::create4(read8, read8, c100, read8_2);
    EXPECT_EQ(2U, concat1->getNumKids());
    EXPECT_EQ(2U, concat1->getKid(1)->getNumKids());
    EXPECT_EQ(2U, concat1->getKid(1)->getKid(1)->getNumKids());

    ref<Expr> extract1 = ExtractExpr::create(concat1, 8, 16);
    EXPECT_EQ(Expr::Concat, extract1->getKind());
    EXPECT_EQ(read8, extract1->getKid(0));
    EXPECT_EQ(c100, extract1->getKid(1));

    ref<Expr> extract2 = ExtractExpr::create(concat1, 6, 26);
    EXPECT_EQ(Expr::Concat, extract2->getKind());
    EXPECT_EQ(read8, extract2->getKid(0));
    EXPECT_EQ(Expr::Concat, extract2->getKid(1)->getKind());
    EXPECT_EQ(read8, extract2->getKid(1)->getKid(0));
    EXPECT_EQ(Expr::Concat, extract2->getKid(1)->getKid(1)->getKind());
    EXPECT_EQ(c100, extract2->getKid(1)->getKid(1)->getKid(0));
    EXPECT_EQ(Expr::Extract, extract2->getKid(1)->getKid(1)->getKid(1)->getKind());

    ref<Expr> extract3 = ExtractExpr::create(concat1, 24, 1);
    EXPECT_EQ(Expr::Extract, extract3->getKind());

    ref<Expr> extract4 = ExtractExpr::create(concat1, 27, 2);
    EXPECT_EQ(Expr::Extract, extract4->getKind());
    const ExtractExpr *tmp = cast<ExtractExpr>(extract4);
    EXPECT_EQ(3U, tmp->getOffset());
    EXPECT_EQ(2U, tmp->getWidth());

    ref<Expr> extract5 = ExtractExpr::create(concat1, 17, 5);
    EXPECT_EQ(Expr::Extract, extract5->getKind());

    ref<Expr> extract6 = ExtractExpr::create(concat1, 3, 26);
    EXPECT_EQ(Expr::Concat, extract6->getKind());
    EXPECT_EQ(Expr::Extract, extract6->getKid(0)->getKind());
    EXPECT_EQ(Expr::Concat, extract6->getKid(1)->getKind());
    EXPECT_EQ(read8, extract6->getKid(1)->getKid(0));
    EXPECT_EQ(Expr::Concat, extract6->getKid(1)->getKid(1)->getKind());
    EXPECT_EQ(c100, extract6->getKid(1)->getKid(1)->getKid(0));
    EXPECT_EQ(Expr::Extract, extract6->getKid(1)->getKid(1)->getKid(1)->getKind());

    ref<Expr> concat10 = ConcatExpr::create4(read8, c100, c100, read8);
    ref<Expr> extract10 = ExtractExpr::create(concat10, 8, 16);
    EXPECT_EQ(Expr::Constant, extract10->getKind());
}

TEST(ExprTest, ExtractConcat) {
    auto array = Array::create("arr2", 256);
    ref<Expr> read64 = ReadExpr::createTempRead(array, 64);

    auto array2 = Array::create("arr3", 256);
    ref<Expr> read8_2 = ReadExpr::createTempRead(array2, 8);

    ref<Expr> extract1 = ExtractExpr::create(read64, 36, 4);
    ref<Expr> extract2 = ExtractExpr::create(read64, 32, 4);

    ref<Expr> extract3 = ExtractExpr::create(read64, 12, 3);
    ref<Expr> extract4 = ExtractExpr::create(read64, 10, 2);
    ref<Expr> extract5 = ExtractExpr::create(read64, 2, 8);

    ref<Expr> kids1[6] = {extract1, extract2, read8_2, extract3, extract4, extract5};
    ref<Expr> concat1 = ConcatExpr::createN(6, kids1);
    EXPECT_EQ(29U, concat1->getWidth());

    ref<Expr> extract6 = ExtractExpr::create(read8_2, 2, 5);
    ref<Expr> extract7 = ExtractExpr::create(read8_2, 1, 1);

    ref<Expr> kids2[3] = {extract1, extract6, extract7};
    ref<Expr> concat2 = ConcatExpr::createN(3, kids2);
    EXPECT_EQ(10U, concat2->getWidth());
    EXPECT_EQ(Expr::Extract, concat2->getKid(0)->getKind());
    EXPECT_EQ(Expr::Extract, concat2->getKid(1)->getKind());
}

///
/// \brief Check that ZExt(Extract(And(X, mask), 0, M)) simplifies to And(X, mask).
///
/// This pattern is common when 32-bit arithmetic is emulated in 64-bit registers:
/// a 64-bit value is masked to 32 bits, extracted to w32, then zero-extended back
/// to w64 — which is redundant since the And already zeroes the upper bits.
///
TEST(ExprTest, ZExtExtractAndMaskSimplification) {
    // Use a 64-bit symbolic expression that is not a ZExt itself
    auto loads = GenerateLoads({"x64"}, Expr::Int64);
    ref<Expr> x64 = loads[0];

    // Build And w64 X 0xffffffff
    ref<Expr> mask = ConstantExpr::create(0xffffffff, Expr::Int64);
    ref<Expr> andExpr = AndExpr::create(x64, mask);

    // ZExt w64 (Extract w32 0 (And w64 X 0xffffffff)) should simplify to andExpr
    ref<Expr> extract = ExtractExpr::create(andExpr, 0, Expr::Int32);
    ref<Expr> zext = ZExtExpr::create(extract, Expr::Int64);
    EXPECT_EQ(andExpr, zext);

    // Also test with a 16-bit mask (w16 inner, w32 outer)
    auto loads32 = GenerateLoads({"x32"}, Expr::Int32);
    ref<Expr> x32 = loads32[0];
    ref<Expr> mask16 = ConstantExpr::create(0xffff, Expr::Int32);
    ref<Expr> andExpr16 = AndExpr::create(x32, mask16);
    ref<Expr> extract16 = ExtractExpr::create(andExpr16, 0, Expr::Int16);
    ref<Expr> zext16 = ZExtExpr::create(extract16, Expr::Int32);
    EXPECT_EQ(andExpr16, zext16);
}

///
/// \brief Check that And(ZExt wN X_M, mask) simplifies to ZExt wN X_M when mask == 2^M-1.
///
/// ZExt already zeros the upper bits, so masking to the inner width is redundant.
///
TEST(ExprTest, AndZExtMaskRedundant) {
    auto loads = GenerateLoads({"a32", "b32"}, Expr::Int32);
    ref<Expr> x32 = loads[0];

    // ZExt w64 X_32
    ref<Expr> zext = ZExtExpr::create(x32, Expr::Int64);

    // And w64 (ZExt w64 X_32) 0xffffffff => ZExt w64 X_32
    ref<Expr> masked = AndExpr::create(zext, ConstantExpr::create(0xffffffff, Expr::Int64));
    EXPECT_EQ(zext, masked);

    // Same check with 16-bit inner width
    auto loads16 = GenerateLoads({"c16"}, Expr::Int16);
    ref<Expr> x16 = loads16[0];
    ref<Expr> zext32 = ZExtExpr::create(x16, Expr::Int32);
    ref<Expr> masked16 = AndExpr::create(zext32, ConstantExpr::create(0xffff, Expr::Int32));
    EXPECT_EQ(zext32, masked16);
}

///
/// \brief Check that And/Or/Xor of two ZExt expressions is pushed inside the ZExt.
///
/// And wN (ZExt wN X_M) (ZExt wN Y_M) => ZExt wN (And wM X_M Y_M)
/// Or  wN (ZExt wN X_M) (ZExt wN Y_M) => ZExt wN (Or  wM X_M Y_M)
/// Xor wN (ZExt wN X_M) (ZExt wN Y_M) => ZExt wN (Xor wM X_M Y_M)
///
/// Since the rule creates new expression nodes, we verify the result structure
/// using getKind() and pointer equality on the leaf operands (x32, y32).
///
TEST(ExprTest, BinaryOpZExtPushdown) {
    auto loads = GenerateLoads({"p32", "q32"}, Expr::Int32);
    ref<Expr> x32 = loads[0];
    ref<Expr> y32 = loads[1];

    ref<Expr> zx = ZExtExpr::create(x32, Expr::Int64);
    ref<Expr> zy = ZExtExpr::create(y32, Expr::Int64);

    // And wN (ZExt X) (ZExt Y) => ZExt wN (And wM X Y)
    ref<Expr> andResult = AndExpr::create(zx, zy);
    ASSERT_EQ(Expr::ZExt, andResult->getKind());
    EXPECT_EQ(Expr::Int64, andResult->getWidth());
    ASSERT_EQ(Expr::And, andResult->getKid(0)->getKind());
    EXPECT_EQ(x32, andResult->getKid(0)->getKid(0));
    EXPECT_EQ(y32, andResult->getKid(0)->getKid(1));

    // Or wN (ZExt X) (ZExt Y) => ZExt wN (Or wM X Y)
    ref<Expr> orResult = OrExpr::create(zx, zy);
    ASSERT_EQ(Expr::ZExt, orResult->getKind());
    EXPECT_EQ(Expr::Int64, orResult->getWidth());
    ASSERT_EQ(Expr::Or, orResult->getKid(0)->getKind());
    EXPECT_EQ(x32, orResult->getKid(0)->getKid(0));
    EXPECT_EQ(y32, orResult->getKid(0)->getKid(1));

    // Xor wN (ZExt X) (ZExt Y) => ZExt wN (Xor wM X Y)
    ref<Expr> xorResult = XorExpr::create(zx, zy);
    ASSERT_EQ(Expr::ZExt, xorResult->getKind());
    EXPECT_EQ(Expr::Int64, xorResult->getWidth());
    ASSERT_EQ(Expr::Xor, xorResult->getKid(0)->getKind());
    EXPECT_EQ(x32, xorResult->getKid(0)->getKid(0));
    EXPECT_EQ(y32, xorResult->getKid(0)->getKid(1));

    // Also verify with 16->32 bit extension
    auto loads16 = GenerateLoads({"r16", "s16"}, Expr::Int16);
    ref<Expr> r16 = loads16[0];
    ref<Expr> s16 = loads16[1];
    ref<Expr> zr = ZExtExpr::create(r16, Expr::Int32);
    ref<Expr> zs = ZExtExpr::create(s16, Expr::Int32);

    ref<Expr> andResult16 = AndExpr::create(zr, zs);
    ASSERT_EQ(Expr::ZExt, andResult16->getKind());
    EXPECT_EQ(Expr::Int32, andResult16->getWidth());
    ASSERT_EQ(Expr::And, andResult16->getKid(0)->getKind());
    EXPECT_EQ(r16, andResult16->getKid(0)->getKid(0));
    EXPECT_EQ(s16, andResult16->getKid(0)->getKid(1));
}

///
/// \brief Check the chained simplification that models 32-bit ops in 64-bit registers.
///
/// The pattern ZExt w64 (Extract w32 0 (And w64 (ZExt w64 X_32) 0xffffffff))
/// should fully collapse through chained rules:
///   1. And(ZExt X, 0xffffffff) => ZExt X      (redundant mask, pointer equality)
///   2. Extract w32 0 (ZExt w64 X_32) => X_32  (existing rule, pointer equality)
///   3. ZExt w64 X_32                           (verify structure)
///
TEST(ExprTest, ZExtRoundtripChain) {
    auto loads = GenerateLoads({"chain32"}, Expr::Int32);
    ref<Expr> x32 = loads[0];

    ref<Expr> zext64 = ZExtExpr::create(x32, Expr::Int64);

    // Step 1: And(ZExt X, mask) => ZExt X (returns the same ZExt pointer)
    ref<Expr> andMasked = AndExpr::create(zext64, ConstantExpr::create(0xffffffff, Expr::Int64));
    EXPECT_EQ(zext64, andMasked);

    // Step 2: Extract w32 0 (ZExt w64 X_32) => X_32 (returns the original x32 pointer)
    ref<Expr> extracted = ExtractExpr::create(andMasked, 0, Expr::Int32);
    EXPECT_EQ(x32, extracted);

    // Step 3: ZExt w64 X_32 — re-extension produces a new ZExt node wrapping x32
    ref<Expr> reExtended = ZExtExpr::create(extracted, Expr::Int64);
    ASSERT_EQ(Expr::ZExt, reExtended->getKind());
    EXPECT_EQ(Expr::Int64, reExtended->getWidth());
    EXPECT_EQ(x32, reExtended->getKid(0));
}

///
/// \brief Check that Ule/Ult/Sle/Slt of identical symbolic expressions simplify.
///
/// Ule x x => true, Ult x x => false, Sle x x => true, Slt x x => false.
///
TEST(ExprTest, CompareIdentical) {
    auto loads = GenerateLoads({"cmp32"}, Expr::Int32);
    ref<Expr> x = loads[0];

    ref<Expr> t = ConstantExpr::create(1, Expr::Bool);
    ref<Expr> f = ConstantExpr::create(0, Expr::Bool);

    EXPECT_EQ(t, UleExpr::create(x, x));
    EXPECT_EQ(f, UltExpr::create(x, x));
    EXPECT_EQ(t, SleExpr::create(x, x));
    EXPECT_EQ(f, SltExpr::create(x, x));
}

///
/// \brief Check that Ule C (Add C (ZExt x)) simplifies to true when no overflow is possible.
///
/// C <= C + ZExt(x) is trivially true because ZExt(x) >= 0 and C + max(ZExt) fits in the width.
///
TEST(ExprTest, UleSelfPlusZExt) {
    auto loads = GenerateLoads({"z32"}, Expr::Int32);
    ref<Expr> x32 = loads[0];

    auto zext = ZExtExpr::create(x32, Expr::Int64);
    auto c = ConstantExpr::create(0x7f5855589c50ULL, Expr::Int64);
    // Add normalises constant to the left: Add(C, ZExt)
    auto add = AddExpr::create(c, zext);
    auto ule = UleExpr::create(c, add);
    EXPECT_EQ(ref<Expr>(ConstantExpr::create(1, Expr::Bool)), ule);

    // Overflow check: if C is large enough that C + UINT32_MAX would overflow, do NOT simplify.
    auto cBig = ConstantExpr::create(UINT64_MAX - 5, Expr::Int64);
    auto addBig = AddExpr::create(cBig, zext);
    auto uleBig = UleExpr::create(cBig, addBig);
    EXPECT_NE(ref<Expr>(ConstantExpr::create(1, Expr::Bool)), uleBig);
}

///
/// \brief Check that Ule (Add C (ZExt (And x mask))) D simplifies to true
///        when C + mask <= D.
///
TEST(ExprTest, UleAddZExtAndMask) {
    auto loads = GenerateLoads({"m32"}, Expr::Int32);
    ref<Expr> x32 = loads[0];

    // N0 = ZExt w64 (And w32 x 0xFF) — max value is 0xFF
    auto mask = ConstantExpr::create(0xFF, Expr::Int32);
    auto inner = AndExpr::create(x32, mask);
    auto zext = ZExtExpr::create(inner, Expr::Int64);

    // C + 0xFF == D  => always true
    auto c = ConstantExpr::create(0x7f5855589c51ULL, Expr::Int64);
    auto d = ConstantExpr::create(0x7f5855589d50ULL, Expr::Int64); // c + 0xFF
    auto add = AddExpr::create(c, zext);
    auto ule = UleExpr::create(add, d);
    EXPECT_EQ(ref<Expr>(ConstantExpr::create(1, Expr::Bool)), ule);

    // C + 0xFF > D  => NOT simplified to true
    auto dSmall = ConstantExpr::create(0x7f5855589d4fULL, Expr::Int64); // c + 0xFF - 1
    auto uleSmall = UleExpr::create(add, dSmall);
    EXPECT_NE(ref<Expr>(ConstantExpr::create(1, Expr::Bool)), uleSmall);
}

} // namespace
