///
/// Copyright (C) 2020, Vitaly Chipounov
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///

#include <iostream>
#include "gtest/gtest.h"

#include <klee/BitfieldSimplifier.h>

using namespace klee;

namespace {

// Checks that (x | 2) & 1 <==> x & 1
TEST(BitfieldSimplifierTest, Test1) {
    BitfieldSimplifier bfs;

    auto array = Array::create("x", 128 / 8);
    auto rd = ReadExpr::createTempRead(array, Expr::Int128);

    auto c1 = ConstantExpr::create(1, Expr::Int128);
    auto c2 = ConstantExpr::create(2, Expr::Int128);

    auto o1 = OrExpr::create(rd, c2);
    auto a1 = AndExpr::create(c1, o1);

    llvm::APInt kzb;
    auto s1 = bfs.simplify(a1, &kzb);
    EXPECT_EQ(AndExpr::create(rd, c1), s1);
}

// Checks that (x & 0xf) | 0xff <==> 0xff
TEST(BitfieldSimplifierTest, Test2) {
    BitfieldSimplifier bfs;

    auto array = Array::create("x", 128 / 8);
    auto rd = ReadExpr::createTempRead(array, Expr::Int128);

    auto c1 = ConstantExpr::create(0xf, Expr::Int128);
    auto c2 = ConstantExpr::create(0xff, Expr::Int128);

    auto o1 = AndExpr::create(rd, c1);
    auto a1 = OrExpr::create(o1, c2);

    llvm::APInt kzb;
    auto s1 = bfs.simplify(a1, &kzb);
    EXPECT_EQ(c2, dyn_cast<ConstantExpr>(s1));
}

// Checks that ((x & 0xff) | 0xff) ^ 0xff <==> 0xff
TEST(BitfieldSimplifierTest, Test3) {
    BitfieldSimplifier bfs;

    auto array = Array::create("x", 128 / 8);
    auto rd = ReadExpr::createTempRead(array, Expr::Int128);

    auto c1 = ConstantExpr::create(0xff, Expr::Int128);
    auto c2 = ConstantExpr::create(0, Expr::Int128);

    auto o1 = AndExpr::create(rd, c1);
    auto o2 = OrExpr::create(o1, c1);
    auto o3 = XorExpr::create(o2, c1);

    llvm::APInt kzb;
    auto s1 = bfs.simplify(o3, &kzb);
    llvm::outs() << s1 << "\n";
    EXPECT_EQ(c2, dyn_cast<ConstantExpr>(s1));
}

// Checks that ((x | 0xff0000) >> 16) & 0xff <==> 0xff
TEST(BitfieldSimplifierTest, Test4) {
    BitfieldSimplifier bfs;

    auto array = Array::create("x", 128 / 8);
    auto rd = ReadExpr::createTempRead(array, Expr::Int128);

    auto c1 = ConstantExpr::create(0xff0000, Expr::Int128);
    auto c2 = ConstantExpr::create(0x10, Expr::Int128);
    auto c3 = ConstantExpr::create(0xff, Expr::Int128);

    auto o1 = OrExpr::create(rd, c1);
    auto o2 = LShrExpr::create(o1, c2);
    auto o3 = AndExpr::create(o2, c3);

    llvm::APInt kzb;
    auto s1 = bfs.simplify(o3, &kzb);
    llvm::outs() << s1 << "\n";
    EXPECT_EQ(c3, dyn_cast<ConstantExpr>(s1));
}

// Checks that x >> 128 <==> 0
TEST(BitfieldSimplifierTest, Test5) {
    BitfieldSimplifier bfs;

    auto array = Array::create("x", 128 / 8);
    auto rd = ReadExpr::createTempRead(array, Expr::Int128);

    auto c1 = ConstantExpr::create(128, Expr::Int128);
    auto c2 = ConstantExpr::create(0, Expr::Int128);

    auto o1 = LShrExpr::create(rd, c1);

    llvm::APInt kzb;
    auto s1 = bfs.simplify(o1, &kzb);
    llvm::outs() << s1 << "\n";
    EXPECT_EQ(c2, dyn_cast<ConstantExpr>(s1));
}

// Checks that (x << 16) & 0xffff <==> 0x0
TEST(BitfieldSimplifierTest, Test6) {
    BitfieldSimplifier bfs;

    auto array = Array::create("x", 128 / 8);
    auto rd = ReadExpr::createTempRead(array, Expr::Int128);

    auto c1 = ConstantExpr::create(0xffff, Expr::Int128);
    auto c2 = ConstantExpr::create(0x10, Expr::Int128);
    auto c3 = ConstantExpr::create(0x0, Expr::Int128);

    auto o1 = ShlExpr::create(rd, c2);
    auto o2 = AndExpr::create(o1, c1);

    llvm::APInt kzb;
    auto s1 = bfs.simplify(o2, &kzb);
    llvm::outs() << s1 << "\n";
    EXPECT_EQ(c3, dyn_cast<ConstantExpr>(s1));
}

// Checks that x << 128 <==> 0
TEST(BitfieldSimplifierTest, Test7) {
    BitfieldSimplifier bfs;

    auto array = Array::create("x", 128 / 8);
    auto rd = ReadExpr::createTempRead(array, Expr::Int128);

    auto c1 = ConstantExpr::create(128, Expr::Int128);
    auto c2 = ConstantExpr::create(0, Expr::Int128);

    auto o1 = ShlExpr::create(rd, c1);

    llvm::APInt kzb;
    auto s1 = bfs.simplify(o1, &kzb);
    llvm::outs() << s1 << "\n";
    EXPECT_EQ(c2, dyn_cast<ConstantExpr>(s1));
}

// Checks that Extract8((x & 0xF), 8) <==> 0
TEST(BitfieldSimplifierTest, Test8) {
    BitfieldSimplifier bfs;

    auto array = Array::create("x", 128 / 8);
    auto rd = ReadExpr::createTempRead(array, Expr::Int128);

    auto c1 = ConstantExpr::create(0xf, Expr::Int128);
    auto c2 = ConstantExpr::create(0, Expr::Int8);

    auto o1 = AndExpr::create(rd, c1);
    auto o2 = ExtractExpr::create(o1, 8, Expr::Int8);

    llvm::APInt kzb;
    auto s1 = bfs.simplify(o2, &kzb);
    llvm::outs() << s1 << "\n";
    EXPECT_EQ(c2, dyn_cast<ConstantExpr>(s1));
}

// Checks that ITE((x | 1) & 1, 0x1, 0x2) <==> 0x1
TEST(BitfieldSimplifierTest, Test9) {
    BitfieldSimplifier bfs;

    auto array = Array::create("x", 128 / 8);
    auto rd = ReadExpr::createTempRead(array, Expr::Int128);

    auto c1 = ConstantExpr::create(0x1, Expr::Int128);
    auto c2 = ConstantExpr::create(0x2, Expr::Int128);

    auto cnd = ExtractExpr::create(AndExpr::create(OrExpr::create(rd, c1), c1), 0, Expr::Bool);
    auto o1 = SelectExpr::create(cnd, c1, c2);

    llvm::APInt kzb;
    auto s1 = bfs.simplify(o1, &kzb);
    llvm::outs() << s1 << "\n";
    EXPECT_EQ(c1, dyn_cast<ConstantExpr>(s1));
}

// Checks that ZExt(x) & 0xff00 <==> 0x0
TEST(BitfieldSimplifierTest, Test10) {
    BitfieldSimplifier bfs;

    auto array = Array::create("x", 8);
    auto rd = ReadExpr::createTempRead(array, Expr::Int8);

    auto c1 = ConstantExpr::create(0xff00, Expr::Int128);
    auto c2 = ConstantExpr::create(0x0, Expr::Int128);

    auto o1 = ZExtExpr::create(rd, Expr::Int128);
    auto o2 = AndExpr::create(o1, c1);

    llvm::APInt kzb;
    auto s1 = bfs.simplify(o2, &kzb);
    llvm::outs() << s1 << "\n";
    EXPECT_EQ(c2, dyn_cast<ConstantExpr>(s1));
}

// Checks that Not(SExt(x | 0x80) >> 15) <==> 0xfffe
TEST(BitfieldSimplifierTest, Test11) {
    BitfieldSimplifier bfs;

    auto array = Array::create("x", 8);
    auto rd = ReadExpr::createTempRead(array, Expr::Int8);

    auto c1 = ConstantExpr::create(0x80, Expr::Int8);
    auto c2 = ConstantExpr::create(0xf, Expr::Int16);
    auto c3 = ConstantExpr::create(0xfffe, Expr::Int16);

    auto o1 = OrExpr::create(rd, c1);
    auto o2 = SExtExpr::create(o1, Expr::Int16);
    auto o3 = LShrExpr::create(o2, c2);
    auto o4 = NotExpr::create(o3);

    llvm::APInt kzb;
    auto s1 = bfs.simplify(o4, &kzb);
    llvm::outs() << s1 << "\n";
    EXPECT_EQ(c3, dyn_cast<ConstantExpr>(s1));
}

} // namespace
