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

#ifndef REGION_MAP_H

#define REGION_MAP_H

#include <inttypes.h>
#include <unordered_map>

#include "IntervalMapWrapper.h"

namespace s2e {
namespace plugins {

template <typename T> using RegionMapIteratorCb = std::function<bool(uint64_t, uint64_t, T)>;

template <typename T> class RegionMap {
protected:
    llvm::IntervalMapWrapper<T> m_map;
    using RM = llvm::IntervalMapWrapper<T>;

public:
    void add(uint64_t start, uint64_t end, T value) {
        assert(start < end);
        m_map.insert(start, end - 1, value);
    }

    void remove(uint64_t start, uint64_t end) {
        assert(start < end);
        typename RM::iterator ie = m_map.end();
        typename RM::iterator it;

        while (((it = m_map.find(start)) != ie) && (it.start() < end)) {
            uint64_t it_addr = it.start();
            uint64_t it_end = it.stop();
            auto value = (*it);
            it.erase();

            if (it_addr < start) {
                m_map.insert(it_addr, start - 1, value);
            }
            if (it_end > end - 1) {
                m_map.insert(end, it_end, value);
            }
        }
    }

    T lookup(uint64_t addr) const {
        return m_map.lookup(addr, T());
    }

    bool lookup(uint64_t addr, uint64_t &start, uint64_t &end, T &value) const {
        auto rit = m_map.find(addr);
        if (rit == m_map.end()) {
            return false;
        }

        start = rit.start();
        end = rit.stop();
        value = *rit;
        return true;
    }

    void iterate(RegionMapIteratorCb<T> &callback) const {
        for (auto rit = m_map.begin(); rit != m_map.end(); ++rit) {
            if (!callback(rit.start(), rit.stop(), *rit)) {
                break;
            }
        }
    }
};

///
/// \brief Maintains a region map for each process id
///
template <typename T> using ProcessRegionMap = std::unordered_map<uint64_t, RegionMap<T>>;

template <typename T> class ProcessRegionMapManager {
protected:
    ProcessRegionMap<T> m_regions;

public:
    void add(uint64_t pid, uint64_t start, uint64_t end, T value) {
        assert(start < end);
        remove(pid, start, end); // TODO: make it faster

        auto &map = m_regions[pid];
        map.add(start, end, value);
    }

    void remove(uint64_t target_pid, uint64_t start, uint64_t end) {
        assert(start < end);
        auto &map = m_regions[target_pid];
        map.remove(start, end);
    }

    void remove(uint64_t pid) {
        auto it = m_regions.find(pid);
        if (it != m_regions.end()) {
            m_regions.erase(it);
        }
    }

    T lookup(uint64_t pid, uint64_t addr) const {
        auto it = m_regions.find(pid);
        if (it == m_regions.end()) {
            return T();
        }

        return (*it).second.lookup(addr);
    }

    bool lookup(uint64_t pid, uint64_t addr, uint64_t &start, uint64_t &end, T &value) const {
        auto it = m_regions.find(pid);
        if (it == m_regions.end()) {
            return false;
        }

        const auto &map = (*it).second;
        return map.lookup(addr, start, end, value);
    }

    void iterate(uint64_t pid, RegionMapIteratorCb<T> &callback) const {
        auto it = m_regions.find(pid);
        if (it == m_regions.end()) {
            return;
        }

        const auto &map = (*it).second;
        map.iterate(callback);
    }
};

} // namespace plugins
} // namespace s2e

#endif