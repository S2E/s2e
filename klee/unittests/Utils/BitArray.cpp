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

#include <klee/util/BitArray.h>

using namespace klee;

namespace {

template <typename T> void SimpleTest() {
    auto size = 0x10000;
    auto ba = BitArrayT<T>::create(size, true);

    for (auto i = 0; i < size; ++i) {
        EXPECT_EQ(true, ba->get(i));
        ba->unset(i);
        EXPECT_EQ(false, ba->get(i));
    }
}

TEST(BitArrayTest, SimpleTest) {
    SimpleTest<uint32_t>();
    SimpleTest<uint64_t>();
}

template <typename T> void BitLookupTest() {
    auto size = 0x10000;
    auto ba = BitArray::create(size, true);

    auto index = 0u;
    auto ret = ba->findFirstSet(index);
    EXPECT_EQ(true, ret);
    EXPECT_EQ(0u, index);
}

TEST(BitArrayTest, BitLookupTest) {
    BitLookupTest<uint32_t>();
    BitLookupTest<uint64_t>();
}

template <typename T> void BitLookupTest1() {
    auto size = 0x10000u;
    auto ba = BitArray::create(size, false);

    auto index = 0u;
    auto ret = ba->findFirstSet(index);
    EXPECT_EQ(false, ret);
    EXPECT_EQ(0u, index);

    for (auto i = 0u; i < size; ++i) {
        ba->set(i);
        auto index = 0u;
        auto ret = ba->findFirstSet(index);
        EXPECT_EQ(true, ret);
        EXPECT_EQ(i, index);
        ba->unset(i);
    }
}

TEST(BitArrayTest, BitLookupTest1) {
    BitLookupTest1<uint32_t>();
    BitLookupTest1<uint64_t>();
}

} // namespace
