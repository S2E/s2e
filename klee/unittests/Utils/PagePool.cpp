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

#include <klee/util/PagePool.h>

using namespace klee;

namespace {

TEST(PagePoolTest, Allocation) {
    auto pages = PagePoolDesc::POOL_PAGE_COUNT;
    auto pp = PagePool::create();
    std::unordered_set<uint8_t *> ptrs;

    for (auto i = 0u; i < pages; ++i) {
        auto ptr = pp->alloc();
        EXPECT_NE(nullptr, ptr);
        EXPECT_EQ(ptrs.end(), ptrs.find(ptr));
        ptrs.insert(ptr);
    }

    EXPECT_EQ(PagePoolDesc::POOL_PAGE_COUNT - pages, pp->getFreePages());

    while (!ptrs.empty()) {
        auto ptr = *ptrs.begin();
        pp->free(ptr);
        ptrs.erase(ptr);
    }

    EXPECT_EQ(0u, pp->getFreePages());
}

TEST(PagePoolTest, AllocationBenchmark) {
    auto pages = 0x1000000u;
    auto pp = PagePool::create();
    std::vector<uint8_t *> vptrs;

    vptrs.reserve(pages);

    for (auto i = 0u; i < pages; ++i) {
        auto ptr = pp->alloc();
        assert(ptr);
        EXPECT_NE(nullptr, ptr);
        vptrs.push_back(ptr);
    }

    while (!vptrs.empty()) {
        auto ptr = vptrs.back();
        // auto ptr = *ptrs.begin();
        pp->free(ptr);
        vptrs.pop_back();
    }

    EXPECT_EQ(0u, pp->getFreePages());
}

} // namespace
