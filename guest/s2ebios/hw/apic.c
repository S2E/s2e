/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2023 Vitaly Chipounov
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

#include <s2e/s2e.h>
#include <utils/interrupt.h>
#include <vmm/vmm.h>

#include "hw.h"
#include "port.h"

static const unsigned APIC_APICID = 0x20;
static const unsigned APIC_APICVER = 0x30;
static const unsigned APIC_TASKPRIOR = 0x80;
static const unsigned APIC_EOI = 0x0B0;
static const unsigned APIC_LDR = 0x0D0;
static const unsigned APIC_DFR = 0x0E0;
static const unsigned APIC_SPURIOUS = 0x0F0;
static const unsigned APIC_ESR = 0x280;
static const unsigned APIC_ICRL = 0x300;
static const unsigned APIC_ICRH = 0x310;
static const unsigned APIC_LVT_TMR = 0x320;
static const unsigned APIC_LVT_PERF = 0x340;
static const unsigned APIC_LVT_LINT0 = 0x350;
static const unsigned APIC_LVT_LINT1 = 0x360;
static const unsigned APIC_LVT_ERR = 0x370;
static const unsigned APIC_TMRINITCNT = 0x380;
static const unsigned APIC_TMRCURRCNT = 0x390;
static const unsigned APIC_TMRDIV = 0x3E0;
static const unsigned APIC_LAST = 0x38F;
static const unsigned APIC_DISABLE = 0x10000;
static const unsigned APIC_SW_ENABLE = 0x100;
static const unsigned APIC_CPUFOCUS = 0x200;
static const unsigned APIC_NMI = (4 << 8);
static const unsigned TMR_PERIODIC = 0x20000;
static const unsigned TMR_BASEDIV = (1 << 20);

#define IA32_APIC_BASE_MSR 0x1B

static uint64_t g_apic_base;

static uint64_t read_msr(uint32_t msr) {
    uint32_t low, high;
    __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
    return ((uint64_t) high << 32) | low;
}

static void write_msr(uint32_t msr, uint64_t value) {
    uint32_t low = value & 0xFFFFFFFF;
    uint32_t high = value >> 32;
    __asm__ volatile("wrmsr" : : "a"(low), "d"(high), "c"(msr));
}

uint64_t get_apic_base(void) {
    return read_msr(IA32_APIC_BASE_MSR) & 0xFFFFF000;
}

void apic_eoi(void) {
    mmio_writel(g_apic_base + APIC_EOI, 0x0);
}

static void apic_timer_isr(uint8_t num) {
    s2e_message("called apic timer int");
    apic_eoi();
}

static void apic_timer_spurious_isr(uint8_t num) {
    s2e_message("called apic timer spurious int");
    apic_eoi();
}

// Set APIC Timer to interrupt every 10ms.
void apic_init(void) {
    uint64_t base = get_apic_base();
    g_apic_base = base;
    vmm_map_page(base, base);

    // interrupts_register(0x20, apic_timer_isr);
    // interrupts_register(0x39, apic_timer_spurious_isr);

    mmio_writel(base + APIC_DFR, 0xffffffff);
    uint64_t ldr = mmio_readl(base + APIC_LDR);
    mmio_writel(base + APIC_LDR, (ldr & 0xffffff) | 1);
    mmio_writel(base + APIC_LVT_TMR, APIC_DISABLE);
    mmio_writel(base + APIC_LVT_PERF, APIC_DISABLE);
    mmio_writel(base + APIC_LVT_LINT0, APIC_DISABLE);
    mmio_writel(base + APIC_LVT_LINT1, APIC_DISABLE);
    mmio_writel(base + APIC_TASKPRIOR, 0);

    uint64_t msr = read_msr(IA32_APIC_BASE_MSR);
    write_msr(IA32_APIC_BASE_MSR, msr | (1 << 11));

    mmio_writel(base + APIC_SPURIOUS, 0xff | APIC_SW_ENABLE);

    /*
    mmio_writel(base + APIC_LVT_TMR, 32 | TMR_PERIODIC);
    mmio_writel(base + APIC_TMRDIV, 3);
    mmio_writel(base + APIC_TMRINITCNT, 3000000);*/
}
