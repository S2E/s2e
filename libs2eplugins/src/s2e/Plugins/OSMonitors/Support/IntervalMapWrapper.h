///
/// Copyright (C) 2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2018, Cyberhaven
/// Copyright (C) 2021, Vitaly Chipounov
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

#ifndef INTERVAL_MAP_WRAPPER_H

#define INTERVAL_MAP_WRAPPER_H

#include <inttypes.h>

#include <llvm/ADT/IntervalMap.h>

namespace llvm {

///
/// \brief Provides an easier to use version of llvm::IntervalMap.
///
/// It is not possible to just use a typedef of `llvm::IntervalMap` because
/// the interval map requires a non-default constructor and the required
/// allocator cannot be copy-constructed on state forks.
///
/// To solve this, create an adapter class that bundles the memory allocator.
///
template <typename T> class IntervalMapWrapper {
public:
    using IM = llvm::IntervalMap<uint64_t, T>;
    using const_iterator = typename IM::const_iterator;
    using iterator = typename IM::iterator;

private:
    // This cannot be a non-static variable because it's used by the
    // parent class but would be destroyed first, causing corruptions.
    typename IM::Allocator m_alloc;

    IM m_map;

public:
    IntervalMapWrapper() : m_alloc(), m_map(m_alloc) {
    }

    IntervalMapWrapper(const IntervalMapWrapper &other) : m_alloc(), m_map(m_alloc) {
        for (auto it = other.begin(); it != other.end(); ++it) {
            insert(it.start(), it.stop(), *it);
        }
    }

    void insert(uint64_t a, uint64_t b, T t) {
        m_map.insert(a, b, t);
    }

    T lookup(uint64_t a, T def = T()) const {
        return m_map.lookup(a, def);
    }

    const_iterator begin() const {
        return m_map.begin();
    }

    iterator begin() {
        return m_map.begin();
    }

    const_iterator end() const {
        return m_map.end();
    }

    iterator end() {
        return m_map.end();
    }

    const_iterator find(uint64_t x) const {
        return m_map.find(x);
    }

    iterator find(uint64_t x) {
        return m_map.find(x);
    }
};

} // namespace llvm

#endif