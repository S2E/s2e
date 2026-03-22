///
/// Copyright (C) 2026, Vitaly Chipounov
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

#ifndef S2E_KVM_HW_H
#define S2E_KVM_HW_H

#include <cassert>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>

#include "device.h"

namespace s2e {
namespace kvm {

class VirtualDeviceManager {
private:
    struct AddressRange {
        uint64_t base;
        uint64_t size;

        bool operator<(const AddressRange &other) const {
            // Non-overlapping ranges: a < b iff a is entirely before b
            return base + size <= other.base;
        }
    };

    using DeviceMap = std::map<AddressRange, std::shared_ptr<VirtualDevice>>;
    DeviceMap m_devices;

    struct LookupResult {
        std::shared_ptr<VirtualDevice> device;
        uint64_t base;
        uint64_t size;
    };

    std::optional<LookupResult> find_device(uint64_t addr) {
        auto it = m_devices.find({addr, 1});
        if (it == m_devices.end()) {
            return std::nullopt;
        }
        return LookupResult{it->second, it->first.base, it->first.size};
    }

public:
    bool register_device(uint64_t base, uint64_t size, std::shared_ptr<VirtualDevice> device) {
        assert(size > 0);
        AddressRange range = {base, size};
        auto result = m_devices.emplace(range, std::move(device));
        return result.second;
    }

    bool rebase_device(uint64_t base, std::shared_ptr<VirtualDevice> device) {
        DeviceMap::iterator found = m_devices.end();
        for (auto it = m_devices.begin(); it != m_devices.end(); ++it) {
            if (it->second == device) {
                found = it;
                break;
            }
        }

        if (found == m_devices.end()) {
            return false;
        }

        auto old_range = found->first;
        AddressRange new_range = {base, old_range.size};

        m_devices.erase(found);

        if (m_devices.count(new_range) > 0) {
            m_devices.emplace(old_range, std::move(device));
            return false;
        }

        m_devices.emplace(new_range, std::move(device));
        return true;
    }

    std::optional<uint64_t> mmio_read(uint64_t addr, unsigned size) {
        auto result = find_device(addr);
        if (!result) {
            return std::nullopt;
        }
        assert(addr >= result->base && addr + size <= result->base + result->size);
        return result->device->mmio_read(addr - result->base, size);
    }

    bool mmio_write(uint64_t addr, uint64_t data, unsigned size) {
        auto result = find_device(addr);
        if (!result) {
            return false;
        }
        assert(addr >= result->base && addr + size <= result->base + result->size);
        result->device->mmio_write(addr - result->base, data, size);
        return true;
    }
};

} // namespace kvm
} // namespace s2e

#endif
