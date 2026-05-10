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
#include <cstring>

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

LocalApic::LocalApic(uint64_t phys_base, CpuInterruptFn cpu_interrupt, CpuExitFn cpu_exit)
    : m_cpu_interrupt(std::move(cpu_interrupt)), m_cpu_exit(std::move(cpu_exit)) {
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

void LocalApic::set_apic_base(uint64_t val) {
    printf("Setting APIC base to %#" PRIx64 "\n", val);
    m_apic_base = (val & ~0xfffULL) | (val & (APICBASE_ENABLE | APICBASE_EXTD));
}

bool LocalApic::enabled() const {
    return m_apic_base & APICBASE_ENABLE;
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
    m_cpu_exit();
}

void LocalApic::set_irq(int vector_num, int trigger_mode) {
    set_bit(m_irr.data(), vector_num);

    if (get_bit(m_tmr.data(), vector_num) != !!trigger_mode) {
        if (trigger_mode) {
            set_bit(m_tmr.data(), vector_num);
        } else {
            reset_bit(m_tmr.data(), vector_num);
        }
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
        case REG_ID:
            if (is_x2apic_mode()) {
                val = m_initial_apic_id;
            } else {
                val = m_id << 24;
            }
            break;
        case REG_VERSION:
            val = m_version | ((LVT_NB - 1) << 16);
            break;
        case REG_TPR:
            val = m_tpr;
            break;
        case REG_APR:
            val = get_arb_pri();
            break;
        case REG_PPR:
            val = get_ppr();
            break;
        case REG_EOI:
            val = 0;
            break;
        case REG_LDR:
            if (is_x2apic_mode()) {
                val = m_extended_log_dest;
            } else {
                val = m_log_dest << 24;
            }
            break;
        case REG_DFR:
            if (is_x2apic_mode()) {
                val = 0;
                ret = -1;
            } else {
                val = (m_dest_mode << 28) | 0xfffffff;
            }
            break;
        case REG_SVR:
            val = m_spurious_vec;
            break;
        case REG_ISR_BASE ... REG_ISR_BASE + 7:
            val = m_isr[index & 7];
            break;
        case REG_TMR_BASE ... REG_TMR_BASE + 7:
            val = m_tmr[index & 7];
            break;
        case REG_IRR_BASE ... REG_IRR_BASE + 7:
            val = m_irr[index & 7];
            break;
        case REG_ESR:
            val = m_esr;
            break;
        case REG_ICR_LO:
        case REG_ICR_HI:
            val = m_icr[index & 1];
            break;
        case REG_LVT_BASE ... REG_LVT_BASE + LVT_NB - 1:
            val = m_lvt[index - REG_LVT_BASE];
            break;
        case REG_TIMER_ICR:
            val = m_initial_count;
            break;
        case REG_TIMER_CCR:
            val = get_current_count();
            break;
        case REG_TIMER_DCR:
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
        case REG_ID:
            if (is_x2apic_mode()) {
                return -1;
            }
            m_id = value >> 24;
            break;
        case REG_VERSION:
            break;
        case REG_TPR:
            m_tpr = value;
            update_irq();
            break;
        case REG_APR:
        case REG_PPR:
            break;
        case REG_EOI:
            eoi();
            break;
        case REG_LDR:
            if (is_x2apic_mode()) {
                return -1;
            }
            m_log_dest = value >> 24;
            break;
        case REG_DFR:
            if (is_x2apic_mode()) {
                return -1;
            }
            m_dest_mode = value >> 28;
            break;
        case REG_SVR:
            m_spurious_vec = value & 0x1ff;
            update_irq();
            break;
        case REG_ISR_BASE ... REG_ISR_BASE + 7:
        case REG_TMR_BASE ... REG_TMR_BASE + 7:
        case REG_IRR_BASE ... REG_IRR_BASE + 7:
        case REG_ESR:
            break;
        case REG_ICR_LO: {
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
        case REG_ICR_HI:
            if (is_x2apic_mode()) {
                return -1;
            }
            m_icr[1] = value;
            break;
        case REG_LVT_BASE ... REG_LVT_BASE + LVT_NB - 1: {
            int n = index - REG_LVT_BASE;
            m_lvt[n] = value;
            if (n == LVT_TIMER) {
                timer_update(libcpu_get_clock_ns(vm_clock));
            }
            break;
        }
        case REG_TIMER_ICR:
            m_initial_count = value;
            m_initial_count_load_time = libcpu_get_clock_ns(vm_clock);
            timer_update(m_initial_count_load_time);
            break;
        case REG_TIMER_CCR:
            break;
        case REG_TIMER_DCR: {
            m_divide_conf = value & 0xb;
            int v = (m_divide_conf & 3) | ((m_divide_conf >> 1) & 4);
            m_count_shift = (v + 1) & 7;
            break;
        }
        case REG_SELF_IPI: {
            if (!is_x2apic_mode()) {
                return -1;
            }
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

    if (!enabled()) {
        printf("APIC MMIO read from offset %#" PRIx64 " ignored because APIC is disabled\n", offset);
        return 0;
    }

    int index = (offset >> 4) & 0xff;
    uint64_t value = 0;
    register_read(index, value);
    return value;
}

void LocalApic::mmio_write(uint64_t offset, uint64_t data, unsigned size) {
    if (size < 4) {
        return;
    }

    if (!enabled()) {
        printf("APIC MMIO write to offset %#" PRIx64 " ignored because APIC is disabled\n", offset);
        return;
    }

    int index = (offset >> 4) & 0xff;
    if (!index) {
        return;
    }

    register_write(index, data);
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

void LocalApic::set_lapic(const kvm_lapic_state *state) {
    auto get = [&](int index) -> uint32_t {
        uint32_t val;
        memcpy(&val, &state->regs[index << 4], sizeof(val));
        return val;
    };

    if (is_x2apic_mode()) {
        m_initial_apic_id = get(REG_ID);
    } else {
        m_id = get(REG_ID) >> 24;
    }

    m_tpr = get(REG_TPR);

    if (is_x2apic_mode()) {
        m_extended_log_dest = get(REG_LDR);
    } else {
        m_log_dest = get(REG_LDR) >> 24;
        m_dest_mode = get(REG_DFR) >> 28;
    }

    m_spurious_vec = get(REG_SVR);

    for (int i = 0; i < 8; i++) {
        m_isr[i] = get(REG_ISR_BASE + i);
        m_tmr[i] = get(REG_TMR_BASE + i);
        m_irr[i] = get(REG_IRR_BASE + i);
    }

    m_esr = get(REG_ESR);
    m_icr[0] = get(REG_ICR_LO);
    m_icr[1] = get(REG_ICR_HI);

    for (int i = 0; i < LVT_NB; i++) {
        m_lvt[i] = get(REG_LVT_BASE + i);
    }

    m_initial_count = get(REG_TIMER_ICR);

    m_divide_conf = get(REG_TIMER_DCR) & 0xb;
    int v = (m_divide_conf & 3) | ((m_divide_conf >> 1) & 4);
    m_count_shift = (v + 1) & 7;

    m_initial_count_load_time = libcpu_get_clock_ns(vm_clock);
    timer_update(m_initial_count_load_time);
    update_irq();
}

void LocalApic::get_lapic(kvm_lapic_state *state) const {
    memset(state->regs, 0, sizeof(state->regs));

    auto put = [&](int index, uint32_t val) { memcpy(&state->regs[index << 4], &val, sizeof(val)); };

    if (is_x2apic_mode()) {
        put(REG_ID, m_initial_apic_id);
    } else {
        put(REG_ID, m_id << 24);
    }

    put(REG_VERSION, m_version | ((LVT_NB - 1) << 16));
    put(REG_TPR, m_tpr);
    put(REG_APR, get_arb_pri());
    put(REG_PPR, get_ppr());

    if (is_x2apic_mode()) {
        put(REG_LDR, m_extended_log_dest);
    } else {
        put(REG_LDR, m_log_dest << 24);
        put(REG_DFR, (m_dest_mode << 28) | 0xfffffff);
    }

    put(REG_SVR, m_spurious_vec);

    for (int i = 0; i < 8; i++) {
        put(REG_ISR_BASE + i, m_isr[i]);
        put(REG_TMR_BASE + i, m_tmr[i]);
        put(REG_IRR_BASE + i, m_irr[i]);
    }

    put(REG_ESR, m_esr);
    put(REG_ICR_LO, m_icr[0]);
    put(REG_ICR_HI, m_icr[1]);

    for (int i = 0; i < LVT_NB; i++) {
        put(REG_LVT_BASE + i, m_lvt[i]);
    }

    put(REG_TIMER_ICR, m_initial_count);
    put(REG_TIMER_CCR, get_current_count());
    put(REG_TIMER_DCR, m_divide_conf);
}

} // namespace kvm
} // namespace s2e
