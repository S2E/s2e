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

#ifndef S2E_KVM_LAPIC_H
#define S2E_KVM_LAPIC_H

#include <array>
#include <cstdint>
#include <functional>

#include "device.h"

struct CPUTimer;

namespace s2e {
namespace kvm {

class LocalApic : public VirtualDevice {
public:
    static constexpr uint64_t APIC_SIZE = 0x1000;
    static constexpr uint64_t APIC_DEFAULT_BASE = 0xfee00000;

    static constexpr int LVT_TIMER = 0;
    static constexpr int LVT_THERMAL = 1;
    static constexpr int LVT_PERFORM = 2;
    static constexpr int LVT_LINT0 = 3;
    static constexpr int LVT_LINT1 = 4;
    static constexpr int LVT_ERROR = 5;
    static constexpr int LVT_NB = 6;

    static constexpr int DM_FIXED = 0;
    static constexpr int DM_LOWPRI = 1;
    static constexpr int DM_SMI = 2;
    static constexpr int DM_NMI = 4;
    static constexpr int DM_INIT = 5;
    static constexpr int DM_SIPI = 6;
    static constexpr int DM_EXTINT = 7;

    static constexpr uint32_t APIC_SV_DIRECTED_IO = (1 << 12);

    // APIC register indices (byte offset >> 4)
    static constexpr int REG_ID = 0x02;
    static constexpr int REG_VERSION = 0x03;
    static constexpr int REG_TPR = 0x08;
    static constexpr int REG_APR = 0x09;
    static constexpr int REG_PPR = 0x0a;
    static constexpr int REG_EOI = 0x0b;
    static constexpr int REG_LDR = 0x0d;
    static constexpr int REG_DFR = 0x0e;
    static constexpr int REG_SVR = 0x0f;
    static constexpr int REG_ISR_BASE = 0x10;
    static constexpr int REG_TMR_BASE = 0x18;
    static constexpr int REG_IRR_BASE = 0x20;
    static constexpr int REG_ESR = 0x28;
    static constexpr int REG_ICR_LO = 0x30;
    static constexpr int REG_ICR_HI = 0x31;
    static constexpr int REG_LVT_BASE = 0x32;
    static constexpr int REG_TIMER_ICR = 0x38;
    static constexpr int REG_TIMER_CCR = 0x39;
    static constexpr int REG_TIMER_DCR = 0x3e;
    static constexpr int REG_SELF_IPI = 0x3f;

    using CpuInterruptFn = std::function<void(int mask, bool reset)>;
    using CpuExitFn = std::function<void(void)>;

    LocalApic(uint64_t phys_base, CpuInterruptFn cpu_interrupt, CpuExitFn cpu_exit);
    ~LocalApic() override;

    uint64_t mmio_read(uint64_t offset, unsigned size) override;
    void mmio_write(uint64_t offset, uint64_t data, unsigned size) override;

    int get_interrupt();
    void deliver_msi(uint32_t addr_lo, uint32_t addr_hi, uint32_t data);
    void get_lapic(kvm_lapic_state *state) const;
    void set_lapic(const kvm_lapic_state *state);

    uint8_t get_tpr() const {
        return m_tpr;
    }
    void set_tpr(uint8_t val);

    uint64_t get_apic_base() const {
        return m_apic_base;
    }

    void set_apic_base(uint64_t val);

    void set_irq(int vector_num, int trigger_mode);

private:
    uint64_t m_apic_base = 0;
    uint8_t m_id = 0;
    uint32_t m_initial_apic_id = 0;
    uint8_t m_version = 0;
    uint8_t m_tpr = 0;
    uint32_t m_spurious_vec = 0;
    uint8_t m_log_dest = 0;
    uint8_t m_dest_mode = 0;
    uint32_t m_extended_log_dest = 0;

    std::array<uint32_t, 8> m_isr = {};
    std::array<uint32_t, 8> m_tmr = {};
    std::array<uint32_t, 8> m_irr = {};
    std::array<uint32_t, LVT_NB> m_lvt = {};
    uint32_t m_esr = 0;
    std::array<uint32_t, 2> m_icr = {};

    uint32_t m_divide_conf = 0;
    int m_count_shift = 0;
    uint32_t m_initial_count = 0;

    CPUTimer *m_timer = nullptr;
    int64_t m_initial_count_load_time = 0;
    int64_t m_next_time = 0;
    int64_t m_timer_expiry = -1;

    CpuInterruptFn m_cpu_interrupt;
    CpuExitFn m_cpu_exit;

    int register_read(int index, uint64_t &value);
    int register_write(int index, uint64_t value);
    void update_irq();
    void deliver_ipi(uint32_t dest, uint8_t dest_mode, uint8_t delivery_mode, uint8_t vector, uint8_t trigger_mode,
                     uint8_t dest_shorthand);

    bool is_x2apic_mode() const;
    int get_ppr() const;
    int get_arb_pri() const;
    void eoi();
    void ioapic_eoi_broadcast(int vector);

    static void timer_callback(void *opaque);
    void on_timer();
    void timer_update(int64_t current_time);
    bool next_timer(int64_t current_time);
    uint32_t get_current_count() const;
    void local_deliver(int vector);
    int irq_pending() const;
    bool enabled() const;

    static void set_bit(uint32_t *tab, int index);
    static int get_bit(const uint32_t *tab, int index);
    static void reset_bit(uint32_t *tab, int index);
    static int get_highest_priority_int(const uint32_t *tab);
};

} // namespace kvm
} // namespace s2e

#endif
