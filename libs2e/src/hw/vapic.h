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

#ifndef S2E_KVM_VAPIC_H
#define S2E_KVM_VAPIC_H

#include <cstdint>

#include "device.h"

namespace s2e {
namespace kvm {

class VirtualApic {
public:
    VirtualApic() = default;
    ~VirtualApic() = default;

    uint8_t get_tpr() const {
        return m_tpr;
    }
    void set_tpr(uint8_t val) {
        m_tpr = val;
    }

    uint64_t get_apic_base() const {
        return m_apic_base;
    }
    void set_apic_base(uint64_t val) {
        m_apic_base = val;
    }

private:
    uint8_t m_tpr = 0;
    uint64_t m_apic_base = 0;
};

} // namespace kvm
} // namespace s2e

#endif
