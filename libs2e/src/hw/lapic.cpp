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

#include <cstdio>

#include <coroutine.h>
#include <cpu/i386/defs.h>
#include <cpu/interrupt.h>
#include <cpu/kvm.h>
#include <timer.h>

#include "../s2e-kvm-vcpu.h"
#include "lapic.h"

namespace s2e {
namespace kvm {

static constexpr uint32_t APICBASE_EXTD = 1 << 10;
static constexpr uint32_t APICBASE_ENABLE = 1 << 11;

static constexpr uint32_t ESR_ILLEGAL_ADDRESS = 1 << 7;

static constexpr uint32_t SV_ENABLE = 1 << 8;

static constexpr uint32_t LVT_MASKED = 1 << 16;
static constexpr uint32_t LVT_LEVEL_TRIGGER = 1 << 15;
static constexpr uint32_t LVT_TIMER_PERIODIC = 1 << 17;
static constexpr uint32_t LVT_TIMER_TSCDEADLINE = 2 << 17;

LocalApic::LocalApic(uint64_t phys_base, CpuInterruptFn cpu_interrupt) : m_cpu_interrupt(std::move(cpu_interrupt)) {
    m_version = 0x14;
    m_apic_base = phys_base | APICBASE_ENABLE;
    m_dest_mode = 0xf;
    m_spurious_vec = 0xff;
    m_lvt.fill(LVT_MASKED);
    m_timer = libcpu_new_timer(vm_clock, 1, timer_callback, this);
}

LocalApic::~LocalApic() {
    libcpu_free_timer(m_timer);
}

void LocalApic::set_tpr(uint8_t val) {
    m_tpr = val;
    update_irq();
}

// TODO: check transitions. Disable => Enable is invalid.
void LocalApic::set_apic_base(uint64_t val) {
    m_apic_base = (val & ~0xfffULL) | (val & (APICBASE_ENABLE | APICBASE_EXTD));
}

///
/// Bit manipulation helpers for 256-bit interrupt registers (ISR, TMR, IRR).
/// Each register is represented as an array of 8 uint32_t words.
///

void LocalApic::set_bit(uint32_t *tab, int index) {
    int i = index >> 5;
    uint32_t mask = 1u << (index & 0x1f);
    tab[i] |= mask;
}

int LocalApic::get_bit(const uint32_t *tab, int index) {
    int i = index >> 5;
    uint32_t mask = 1u << (index & 0x1f);
    return !!(tab[i] & mask);
}

void LocalApic::reset_bit(uint32_t *tab, int index) {
    int i = index >> 5;
    uint32_t mask = 1u << (index & 0x1f);
    tab[i] &= ~mask;
}

int LocalApic::get_highest_priority_int(const uint32_t *tab) {
    for (int i = 7; i >= 0; i--) {
        if (tab[i] != 0) {
            return i * 32 + (31 - __builtin_clz(tab[i]));
        }
    }
    return -1;
}

bool LocalApic::is_x2apic_mode() const {
    return m_apic_base & APICBASE_EXTD;
}

int LocalApic::get_ppr() const {
    int tpr = m_tpr >> 4;
    int isrv = get_highest_priority_int(m_isr.data());
    if (isrv < 0) {
        isrv = 0;
    }
    isrv >>= 4;
    if (tpr >= isrv) {
        return m_tpr;
    }
    return isrv << 4;
}

int LocalApic::get_arb_pri() const {
    return 0;
}

void LocalApic::update_irq() {
    if (irq_pending() > 0) {
        m_cpu_interrupt(CPU_INTERRUPT_HARD, false);
    } else {
        m_cpu_interrupt(CPU_INTERRUPT_HARD, true);
    }
}

void LocalApic::eoi() {
    int isrv = get_highest_priority_int(m_isr.data());
    if (isrv < 0) {
        return;
    }
    reset_bit(m_isr.data(), isrv);

    if (!(m_spurious_vec & APIC_SV_DIRECTED_IO) && get_bit(m_tmr.data(), isrv)) {
        ioapic_eoi_broadcast(isrv);
    }

    update_irq();
}

void LocalApic::ioapic_eoi_broadcast(int vector) {
    g_kvm_vcpu_buffer->exit_reason = KVM_EXIT_IOAPIC_EOI;
    g_kvm_vcpu_buffer->eoi.vector = vector;
    coroutine_yield();
}

void LocalApic::set_irq(int vector_num, int trigger_mode) {
    set_bit(m_irr.data(), vector_num);
    if (trigger_mode) {
        set_bit(m_tmr.data(), vector_num);
    } else {
        reset_bit(m_tmr.data(), vector_num);
    }
    update_irq();
}

int LocalApic::irq_pending() const {
    if (!(m_spurious_vec & SV_ENABLE)) {
        return 0;
    }

    int irrv = get_highest_priority_int(m_irr.data());
    if (irrv < 0) {
        return 0;
    }

    int ppr = get_ppr();
    if (ppr && (irrv & 0xf0) <= (ppr & 0xf0)) {
        return -1;
    }

    return irrv;
}

int LocalApic::get_interrupt() {
    if (!(m_spurious_vec & SV_ENABLE)) {
        return -1;
    }

    int intno = irq_pending();

    if (intno == 0) {
        return -1;
    } else if (intno < 0) {
        return m_spurious_vec & 0xff;
    }

    reset_bit(m_irr.data(), intno);
    set_bit(m_isr.data(), intno);

    return intno;
}

void LocalApic::local_deliver(int vector) {
    uint32_t lvt = m_lvt[vector];

    if (lvt & LVT_MASKED) {
        return;
    }

    int delivery_mode = (lvt >> 8) & 7;
    switch (delivery_mode) {
        case DM_FIXED: {
            int trigger_mode = 0;
            if ((vector == LVT_LINT0 || vector == LVT_LINT1) && (lvt & LVT_LEVEL_TRIGGER)) {
                trigger_mode = 1;
            }
            set_irq(lvt & 0xff, trigger_mode);
            break;
        }
        case DM_SMI:
            m_cpu_interrupt(CPU_INTERRUPT_SMI, false);
            break;
        case DM_NMI:
            m_cpu_interrupt(CPU_INTERRUPT_NMI, false);
            break;
        case DM_EXTINT:
            m_cpu_interrupt(CPU_INTERRUPT_HARD, false);
            break;
        default:
            break;
    }
}

void LocalApic::timer_callback(void *opaque) {
    static_cast<LocalApic *>(opaque)->on_timer();
}

void LocalApic::on_timer() {
    local_deliver(LVT_TIMER);
    timer_update(m_next_time);
}

bool LocalApic::next_timer(int64_t current_time) {
    m_timer_expiry = -1;

    if (m_lvt[LVT_TIMER] & LVT_TIMER_TSCDEADLINE) {
        return false;
    }

    int64_t d = (current_time - m_initial_count_load_time) >> m_count_shift;

    if (m_lvt[LVT_TIMER] & LVT_TIMER_PERIODIC) {
        if (!m_initial_count) {
            return false;
        }
        d = ((d / ((uint64_t) m_initial_count + 1)) + 1) * ((uint64_t) m_initial_count + 1);
    } else {
        if (d >= m_initial_count) {
            return false;
        }
        d = (uint64_t) m_initial_count + 1;
    }

    m_next_time = m_initial_count_load_time + (d << m_count_shift);
    m_timer_expiry = m_next_time;
    return true;
}

void LocalApic::timer_update(int64_t current_time) {
    if (next_timer(current_time)) {
        libcpu_mod_timer_ns(m_timer, m_next_time);
    } else {
        libcpu_del_timer(m_timer);
    }
}

uint32_t LocalApic::get_current_count() const {
    if (!m_initial_count) {
        return 0;
    }

    int64_t d = (libcpu_get_clock_ns(vm_clock) - m_initial_count_load_time) >> m_count_shift;

    if (m_lvt[LVT_TIMER] & LVT_TIMER_PERIODIC) {
        d = ((unsigned) d % ((uint64_t) m_initial_count + 1));
    } else {
        if (d >= m_initial_count) {
            return 0;
        }
    }

    return m_initial_count - d;
}

int LocalApic::register_read(int index, uint64_t &value) {
    uint32_t val;
    int ret = 0;

    switch (index) {
        case 0x02:
            if (is_x2apic_mode()) {
                val = m_initial_apic_id;
            } else {
                val = m_id << 24;
            }
            break;
        case 0x03:
            val = m_version | ((LVT_NB - 1) << 16);
            break;
        case 0x08:
            val = m_tpr;
            break;
        case 0x09:
            val = get_arb_pri();
            break;
        case 0x0a:
            val = get_ppr();
            break;
        case 0x0b:
            val = 0;
            break;
        case 0x0d:
            if (is_x2apic_mode()) {
                val = m_extended_log_dest;
            } else {
                val = m_log_dest << 24;
            }
            break;
        case 0x0e:
            if (is_x2apic_mode()) {
                val = 0;
                ret = -1;
            } else {
                val = (m_dest_mode << 28) | 0xfffffff;
            }
            break;
        case 0x0f:
            val = m_spurious_vec;
            break;
        case 0x10 ... 0x17:
            val = m_isr[index & 7];
            break;
        case 0x18 ... 0x1f:
            val = m_tmr[index & 7];
            break;
        case 0x20 ... 0x27:
            val = m_irr[index & 7];
            break;
        case 0x28:
            val = m_esr;
            break;
        case 0x30:
        case 0x31:
            val = m_icr[index & 1];
            break;
        case 0x32 ... 0x37:
            val = m_lvt[index - 0x32];
            break;
        case 0x38:
            val = m_initial_count;
            break;
        case 0x39:
            val = get_current_count();
            break;
        case 0x3e:
            val = m_divide_conf;
            break;
        default:
            m_esr |= ESR_ILLEGAL_ADDRESS;
            val = 0;
            ret = -1;
            break;
    }

    value = val;
    return ret;
}

int LocalApic::register_write(int index, uint64_t value) {
    switch (index) {
        case 0x02:
            if (is_x2apic_mode()) {
                return -1;
            }
            m_id = value >> 24;
            break;
        case 0x03:
            break;
        case 0x08:
            m_tpr = value;
            update_irq();
            break;
        case 0x09:
        case 0x0a:
            break;
        case 0x0b:
            eoi();
            break;
        case 0x0d:
            if (is_x2apic_mode()) {
                return -1;
            }
            m_log_dest = value >> 24;
            break;
        case 0x0e:
            if (is_x2apic_mode()) {
                return -1;
            }
            m_dest_mode = value >> 28;
            break;
        case 0x0f:
            m_spurious_vec = value & 0x1ff;
            update_irq();
            break;
        case 0x10 ... 0x17:
        case 0x18 ... 0x1f:
        case 0x20 ... 0x27:
        case 0x28:
            break;
        case 0x30: {
            uint32_t dest;

            m_icr[0] = value;
            if (is_x2apic_mode()) {
                m_icr[1] = value >> 32;
                dest = m_icr[1];
            } else {
                dest = (m_icr[1] >> 24) & 0xff;
            }

            deliver_ipi(dest, (m_icr[0] >> 11) & 1, (m_icr[0] >> 8) & 7, m_icr[0] & 0xff, (m_icr[0] >> 15) & 1,
                        (m_icr[0] >> 18) & 3);
            break;
        }
        case 0x31:
            if (is_x2apic_mode()) {
                return -1;
            }
            m_icr[1] = value;
            break;
        case 0x32 ... 0x37: {
            int n = index - 0x32;
            m_lvt[n] = value;
            if (n == LVT_TIMER) {
                timer_update(libcpu_get_clock_ns(vm_clock));
            }
            break;
        }
        case 0x38:
            m_initial_count = value;
            m_initial_count_load_time = libcpu_get_clock_ns(vm_clock);
            timer_update(m_initial_count_load_time);
            break;
        case 0x39:
            break;
        case 0x3e: {
            m_divide_conf = value & 0xb;
            int v = (m_divide_conf & 3) | ((m_divide_conf >> 1) & 4);
            m_count_shift = (v + 1) & 7;
            break;
        }
        case 0x3f: {
            if (!is_x2apic_mode()) {
                return -1;
            }
            // Self-IPI in x2APIC mode: vector in bits 0-7
            int vector = value & 0xff;
            set_irq(vector, 0);
            break;
        }
        default:
            m_esr |= ESR_ILLEGAL_ADDRESS;
            return -1;
    }

    return 0;
}

uint64_t LocalApic::mmio_read(uint64_t offset, unsigned size) {
    if (size < 4) {
        return 0;
    }

    int index = (offset >> 4) & 0xff;
    uint64_t value = 0;
    register_read(index, value);
    return value;
}

void LocalApic::deliver_ipi(uint32_t dest, uint8_t dest_mode, uint8_t delivery_mode, uint8_t vector,
                            uint8_t trigger_mode, uint8_t dest_shorthand) {
    bool deliver_to_self = false;

    // Determine if this IPI should be delivered to self
    switch (dest_shorthand) {
        case 0: {
            // No shorthand - check destination field
            if (is_x2apic_mode()) {
                deliver_to_self = (dest == m_initial_apic_id);
            } else {
                deliver_to_self = (dest == m_id);
            }
            break;
        }
        case 1:
            // Self
            deliver_to_self = true;
            break;
        case 2:
            // All including self
            deliver_to_self = true;
            printf("lapic: IPI to all including self not fully implemented (treating as self)\n");
            break;
        case 3:
            // All excluding self
            printf("lapic: IPI to all excluding self not implemented\n");
            return;
    }

    if (!deliver_to_self) {
        // Destination is not this APIC
        printf("lapic: IPI to other CPU not implemented (dest=%u)\n", dest);
        return;
    }

    // Handle INIT level de-assert
    if (delivery_mode == DM_INIT) {
        int level = (m_icr[0] >> 14) & 1;
        if (level == 0 && trigger_mode == 1) {
            // INIT level de-assert - arbitration ID update, not needed for single CPU
            return;
        }
        printf("lapic: INIT IPI not implemented\n");
        return;
    }

    // Handle SIPI
    if (delivery_mode == DM_SIPI) {
        printf("lapic: SIPI not implemented\n");
        return;
    }

    // Deliver to self
    switch (delivery_mode) {
        case DM_FIXED:
        case DM_LOWPRI:
            set_irq(vector, trigger_mode);
            break;
        case DM_SMI:
            m_cpu_interrupt(CPU_INTERRUPT_SMI, false);
            break;
        case DM_NMI:
            m_cpu_interrupt(CPU_INTERRUPT_NMI, false);
            break;
        default:
            break;
    }
}

void LocalApic::deliver_msi(uint32_t addr_lo, uint32_t addr_hi, uint32_t data) {
    int vector = data & 0xff;
    int delivery_mode = (data >> 8) & 7;
    int trigger_mode = (data >> 15) & 1;

    switch (delivery_mode) {
        case DM_FIXED:
        case DM_LOWPRI:
            set_irq(vector, trigger_mode);
            break;
        case DM_SMI:
            m_cpu_interrupt(CPU_INTERRUPT_SMI, false);
            break;
        case DM_NMI:
            m_cpu_interrupt(CPU_INTERRUPT_NMI, false);
            break;
        case DM_EXTINT:
            m_cpu_interrupt(CPU_INTERRUPT_HARD, false);
            break;
        default:
            break;
    }
}

void LocalApic::mmio_write(uint64_t offset, uint64_t data, unsigned size) {
    if (size < 4) {
        return;
    }

    int index = (offset >> 4) & 0xff;
    if (!index) {
        return;
    }

    register_write(index, data);
}

} // namespace kvm
} // namespace s2e
