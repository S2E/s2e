///
/// Copyright (C) 2022, Vitaly Chipounov
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
#include <memory>
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include <klee/AddressSpace.h>
#include <klee/ExecutionState.h>

using namespace klee;
using ::testing::_;

namespace {

class TestAsNotify : public IAddressSpaceNotification {
public:
    MOCK_METHOD(void, addressSpaceChange,
                (const ObjectKey &key, const ObjectStateConstPtr &oldState, const ObjectStatePtr &newState),
                (override));
    MOCK_METHOD(void, addressSpaceObjectSplit,
                (const ObjectStateConstPtr &oldObject, const std::vector<ObjectStatePtr> &newObjects), (override));
    MOCK_METHOD(void, addressSpaceSymbolicStatusChange, (const ObjectStatePtr &object, bool becameConcrete),
                (override));
};

void InitAs(TestAsNotify &notify, AddressSpace &as) {
    const auto size = 0x1000;
    for (auto i = 0x1000; i < 1024 * 1024; i += size) {
        auto mo = ObjectState::allocate(i, size, true);
        mo->setNotifyOnConcretenessChange(true);
        mo->setSplittable(true);
        EXPECT_CALL(notify, addressSpaceChange).Times(1);
        as.bindObject(mo);
    }
}

std::vector<uint8_t> GetBuffer(size_t size) {
    std::vector<uint8_t> ret;
    for (size_t i = 0; i < size; ++i) {
        ret.push_back((uint8_t) i);
    }
    return ret;
}

TEST(AddressSpaceTest, WriteConcreteReadConcrete) {
    TestAsNotify notify;
    auto as = std::make_unique<AddressSpace>(&notify);
    InitAs(notify, *as);

    auto in = GetBuffer(0x10000);
    EXPECT_EQ(as->write(0x1fff, in.data(), in.size()), true);

    // Read concrete
    auto out = std::vector<uint8_t>(in.size());
    EXPECT_EQ(as->read(0x1fff, out.data(), out.size(), nullptr), true);

    EXPECT_EQ(out, in);
    EXPECT_EQ(out[0xffff], 0xff);
}

TEST(AddressSpaceTest, WriteConcreteReadSymbolic) {
    TestAsNotify notify;
    auto as = std::make_unique<AddressSpace>(&notify);
    InitAs(notify, *as);

    auto in = GetBuffer(0x10000);
    EXPECT_EQ(as->write(0x1fff, in.data(), in.size()), true);

    // Read symbolic
    std::vector<klee::ref<klee::Expr>> outSymb;
    EXPECT_EQ(as->read(0x1fff, outSymb, in.size()), true);
    for (size_t i = 0; i < in.size(); ++i) {
        auto ce = dyn_cast<ConstantExpr>(outSymb[i]);
        EXPECT_EQ(ce->getZExtValue(), in[i]);
    }
}

TEST(AddressSpaceTest, WriteConcreteReadSymbolicValueLittleEndian) {
    Context::initialize(true, klee::Expr::Int64);

    TestAsNotify notify;
    auto as = std::make_unique<AddressSpace>(&notify);
    InitAs(notify, *as);

    auto in = GetBuffer(0x2000);
    EXPECT_EQ(as->write(0x1fff, in.data(), in.size()), true);

    // Read symbolic buffer
    auto e = as->read(0x2000, Expr::Bool);
    EXPECT_NE(e.get(), nullptr);
    EXPECT_EQ(dyn_cast<ConstantExpr>(e)->getZExtValue(), 1u);

    e = as->read(0x2000, Expr::Int8);
    EXPECT_NE(e.get(), nullptr);
    EXPECT_EQ(dyn_cast<ConstantExpr>(e)->getZExtValue(), 1u);

    e = as->read(0x1fff, Expr::Int16);
    EXPECT_NE(e.get(), nullptr);
    EXPECT_EQ(dyn_cast<ConstantExpr>(e)->getZExtValue(), 0x0100u);

    e = as->read(0x1fff, Expr::Int32);
    EXPECT_NE(e.get(), nullptr);
    EXPECT_EQ(dyn_cast<ConstantExpr>(e)->getZExtValue(), 0x03020100u);

    e = as->read(0x1fff, Expr::Int64);
    EXPECT_NE(e.get(), nullptr);
    EXPECT_EQ(dyn_cast<ConstantExpr>(e)->getZExtValue(), 0x0706050403020100u);

    e = as->read(0x1fff, 9);
    EXPECT_EQ(e.get(), nullptr);
}

TEST(AddressSpaceTest, WriteConcreteReadSymbolicValueBigEndian) {
    Context::initialize(false, klee::Expr::Int64);

    TestAsNotify notify;
    auto as = std::make_unique<AddressSpace>(&notify);
    InitAs(notify, *as);

    auto in = GetBuffer(0x2000);
    EXPECT_EQ(as->write(0x1fff, in.data(), in.size()), true);

    // Read symbolic buffer
    auto e = as->read(0x2000, Expr::Bool);
    EXPECT_NE(e.get(), nullptr);
    EXPECT_EQ(dyn_cast<ConstantExpr>(e)->getZExtValue(), 1u);

    e = as->read(0x2000, Expr::Int8);
    EXPECT_NE(e.get(), nullptr);
    EXPECT_EQ(dyn_cast<ConstantExpr>(e)->getZExtValue(), 1u);

    e = as->read(0x1fff, Expr::Int16);
    EXPECT_NE(e.get(), nullptr);
    EXPECT_EQ(dyn_cast<ConstantExpr>(e)->getZExtValue(), 0x0001u);

    e = as->read(0x1fff, Expr::Int32);
    EXPECT_NE(e.get(), nullptr);
    EXPECT_EQ(dyn_cast<ConstantExpr>(e)->getZExtValue(), 0x00010203u);

    e = as->read(0x1fff, Expr::Int64);
    EXPECT_NE(e.get(), nullptr);
    EXPECT_EQ(dyn_cast<ConstantExpr>(e)->getZExtValue(), 0x0001020304050607u);
}

TEST(AddressSpaceTest, WriteSymbolicReadSymbolicValueLittleEndian) {
    Context::initialize(true, klee::Expr::Int64);

    TestAsNotify notify;
    auto as = std::make_unique<AddressSpace>(&notify);
    InitAs(notify, *as);

    auto in = klee::ConstantExpr::create(0x0706050403020100, klee::Expr::Int64);
    EXPECT_EQ(as->write(0x1fff, in, nullptr), true);

    // Read concrete
    auto out = std::vector<uint8_t>(8);
    EXPECT_EQ(as->read(0x1fff, out.data(), out.size(), nullptr), true);
    for (auto i = 0u; i < out.size(); ++i) {
        EXPECT_EQ(out[i], i);
    }

    // Read symbolic buffer
    auto e = as->read(0x2000, Expr::Bool);
    EXPECT_NE(e.get(), nullptr);
    EXPECT_EQ(dyn_cast<ConstantExpr>(e)->getZExtValue(), 1u);

    e = as->read(0x2000, Expr::Int8);
    EXPECT_NE(e.get(), nullptr);
    EXPECT_EQ(dyn_cast<ConstantExpr>(e)->getZExtValue(), 1u);

    e = as->read(0x1fff, Expr::Int16);
    EXPECT_NE(e.get(), nullptr);
    EXPECT_EQ(dyn_cast<ConstantExpr>(e)->getZExtValue(), 0x0100u);

    e = as->read(0x1fff, Expr::Int32);
    EXPECT_NE(e.get(), nullptr);
    EXPECT_EQ(dyn_cast<ConstantExpr>(e)->getZExtValue(), 0x03020100u);

    e = as->read(0x1fff, Expr::Int64);
    EXPECT_NE(e.get(), nullptr);
    EXPECT_EQ(dyn_cast<ConstantExpr>(e)->getZExtValue(), 0x0706050403020100u);

    e = as->read(0x1fff, 9);
    EXPECT_EQ(e.get(), nullptr);
}

TEST(AddressSpaceTest, WriteSymbolicReadSymbolicValueBigEndian) {
    Context::initialize(false, klee::Expr::Int64);

    TestAsNotify notify;
    auto as = std::make_unique<AddressSpace>(&notify);
    InitAs(notify, *as);

    auto in = klee::ConstantExpr::create(0x0706050403020100, klee::Expr::Int64);
    EXPECT_EQ(as->write(0x1fff, in, nullptr), true);

    // Read concrete
    auto out = std::vector<uint8_t>(8);
    EXPECT_EQ(as->read(0x1fff, out.data(), out.size(), nullptr), true);
    for (auto i = 0u; i < out.size(); ++i) {
        EXPECT_EQ(out[7 - i], i);
    }

    // Read symbolic buffer
    auto e = as->read(0x2000, Expr::Bool);
    EXPECT_NE(e.get(), nullptr);
    EXPECT_EQ(dyn_cast<ConstantExpr>(e)->getZExtValue(), 0u);

    e = as->read(0x2000, Expr::Int8);
    EXPECT_NE(e.get(), nullptr);
    EXPECT_EQ(dyn_cast<ConstantExpr>(e)->getZExtValue(), 6u);

    e = as->read(0x1fff, Expr::Int16);
    EXPECT_NE(e.get(), nullptr);
    EXPECT_EQ(dyn_cast<ConstantExpr>(e)->getZExtValue(), 0x0706u);

    e = as->read(0x1fff, Expr::Int32);
    EXPECT_NE(e.get(), nullptr);
    EXPECT_EQ(dyn_cast<ConstantExpr>(e)->getZExtValue(), 0x07060504u);

    e = as->read(0x1fff, Expr::Int64);
    EXPECT_NE(e.get(), nullptr);
    EXPECT_EQ(dyn_cast<ConstantExpr>(e)->getZExtValue(), 0x0706050403020100u);

    e = as->read(0x1fff, 9);
    EXPECT_EQ(e.get(), nullptr);
}

TEST(AddressSpaceTest, ReadWriteBadAddress) {
    Context::initialize(false, klee::Expr::Int64);

    TestAsNotify notify;
    auto as = std::make_unique<AddressSpace>(&notify);

    auto in = klee::ConstantExpr::create(0x0706050403020100, klee::Expr::Int64);
    EXPECT_EQ(as->write(0x1fff, in, nullptr), false);

    auto e = as->read(0x2000, 1);
    EXPECT_EQ(e.get(), nullptr);
}

TEST(AddressSpaceTest, ConcretizationAndNotification) {
    Context::initialize(false, klee::Expr::Int64);

    TestAsNotify notify;
    auto as = std::make_unique<AddressSpace>(&notify);
    InitAs(notify, *as);

    auto array = Array::create("symb", 8, nullptr, nullptr, "symb");
    auto expr = ReadExpr::createTempRead(array, klee::Expr::Int64);
    EXPECT_CALL(notify, addressSpaceSymbolicStatusChange).Times(2);
    EXPECT_EQ(as->write(0x1fff, expr, nullptr), true);

    uint8_t chr;
    EXPECT_EQ(as->read(0x1fff, &chr, sizeof(chr), nullptr), false);

    auto concretizer = [&](const ref<Expr> &e, const ObjectStateConstPtr &mo, size_t offset) -> uint8_t {
        return 0xab;
    };

    EXPECT_EQ(as->read(0x1fff, &chr, sizeof(chr), concretizer), true);
    ASSERT_EQ(chr, 0xab);

    expr = klee::ConstantExpr::create(0x0706050403020100, klee::Expr::Int64);
    EXPECT_CALL(notify, addressSpaceSymbolicStatusChange).Times(1);
    EXPECT_EQ(as->write(0x2000, expr, nullptr), true);

    EXPECT_CALL(notify, addressSpaceSymbolicStatusChange).Times(1);
    EXPECT_EQ(as->write(0x1fff, expr, nullptr), true);
}

TEST(AddressSpaceTest, AddressTranslation) {
    Context::initialize(false, klee::Expr::Int64);

    TestAsNotify notify;
    auto as = std::make_unique<AddressSpace>(&notify);
    InitAs(notify, *as);

    auto translate = [](uint64_t address, uint64_t &hostAddress) -> bool {
        hostAddress = address & 0xFFFFFFF;
        return true;
    };

    auto in = GetBuffer(0x10000);
    EXPECT_EQ(as->write(0xF0001fff, in.data(), in.size(), translate), true);

    // Read concrete
    auto out = std::vector<uint8_t>(in.size());
    EXPECT_EQ(as->read(0xF0001fff, out.data(), out.size(), nullptr, translate), true);

    EXPECT_EQ(out, in);
    EXPECT_EQ(out[0xffff], 0xff);
}

TEST(AddressSpaceTest, CheckSymbolic) {
    Context::initialize(false, klee::Expr::Int64);

    TestAsNotify notify;
    auto as = std::make_unique<AddressSpace>(&notify);
    InitAs(notify, *as);

    auto array = Array::create("symb", 8, nullptr, nullptr, "symb");
    auto expr = ReadExpr::createTempRead(array, klee::Expr::Int64);
    EXPECT_CALL(notify, addressSpaceSymbolicStatusChange).Times(2);
    EXPECT_EQ(as->write(0x1fff, expr, nullptr), true);

    EXPECT_EQ(as->symbolic(0x1ff0, 1), false);
    EXPECT_EQ(as->symbolic(0x1fff, 1), true);
    EXPECT_EQ(as->symbolic(0x2000, 245), true);
}

TEST(AddressSpaceTest, ObjectSplit) {
    TestAsNotify notify;
    auto as = std::make_unique<AddressSpace>(&notify);
    InitAs(notify, *as);

    auto in = GetBuffer(0x10000);
    EXPECT_EQ(as->write(0x1fff, in.data(), in.size()), true);

    for (auto i = 0x1000; i < 0x11000; i += 0x1000) {
        auto os = as->findObject(i);
        ResolutionList rl;
        EXPECT_CALL(notify, addressSpaceChange).Times(33);
        EXPECT_CALL(notify, addressSpaceObjectSplit).Times(1);
        EXPECT_EQ(as->splitMemoryObject(notify, os, rl), true);
        EXPECT_EQ(rl.size(), 0x1000u / 128u);
    }

    // Read symbolic
    std::vector<klee::ref<klee::Expr>> outSymb;
    EXPECT_EQ(as->read(0x1fff, outSymb, in.size()), true);
    for (size_t i = 0; i < in.size(); ++i) {
        auto ce = dyn_cast<ConstantExpr>(outSymb[i]);
        EXPECT_EQ(ce->getZExtValue(), in[i]);
    }
}

} // namespace
