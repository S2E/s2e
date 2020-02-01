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

#include <klee/Internal/ADT/ImmutableMap.h>

using namespace klee;

namespace {

struct Key {
    uint64_t address;
    unsigned size;

    bool operator<(const Key &a) const {
        return address + size <= a.address;
    }
};

TEST(ImmutableMapTest, Simple1) {
    typedef ImmutableMap<Key, uint64_t> MyMap;

    MyMap map;
    const unsigned MAX_COUNT = 1000000;

    for (unsigned i = 0; i < MAX_COUNT; i += 100) {
        Key key;
        key.address = i;
        key.size = 30;
        map = map.insert(std::make_pair(key, i));
    }

    for (unsigned i = 0; i < MAX_COUNT; i += 100) {
        Key key;
        key.address = i;
        key.size = 1;
        EXPECT_EQ(1ul, map.count(key));

        auto it = map.find(key);
        // EXPECT_NE(map.end(), it);
        EXPECT_EQ(i, (*it).first.address);
        EXPECT_EQ(30ul, (*it).first.size);
    }

    ASSERT_EQ(MAX_COUNT / 100, map.size());
}
} // namespace
