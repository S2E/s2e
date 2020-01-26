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
} // namespace
