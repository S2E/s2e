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

#include <inttypes.h>
#include <stdio.h>

#include <hw/port.h>
#include <utils/interrupt.h>
#include <vmm/vmm.h>
#include "hw.h"

#define IOAPIC_REG_SELECT 0x00
#define IOAPIC_REG_WINDOW 0x10

#define IOAPIC_ID     0x0
#define IOAPIC_VER    0x1
#define IOAPIC_ARB    0x2
#define IOAPIC_REDTBL 0x10

struct IOAPIC_Redirection_Entry {
    uint32_t Vector : 8;
    uint32_t DeliveryMode : 3;
    uint32_t DestinationMode : 1;
    uint32_t DeliveryStatus : 1;
    uint32_t Polarity : 1;
    uint32_t RemoteIRR : 1;
    uint32_t TriggerMode : 1;
    uint32_t Mask : 1;
    uint32_t Reserved : 15;
    uint32_t DestinationField : 8;
    uint32_t Reserved2 : 24;
} __attribute__((packed));

static volatile uintptr_t s_ioapic = (uintptr_t) 0xFEC00000;

void write_ioapic_reg(uint32_t reg, uint32_t value) {
    mmio_writel(s_ioapic + IOAPIC_REG_SELECT, reg);
    mmio_writel(s_ioapic + IOAPIC_REG_WINDOW, value);
}

uint32_t read_ioapic_reg(uint32_t reg) {
    mmio_writel(s_ioapic + IOAPIC_REG_SELECT, reg);
    return mmio_readl(s_ioapic + IOAPIC_REG_WINDOW);
}

#define TIMER_IRQ_ID   0x20
#define TIME_PORT_CTRL 0x43    /* Control register port for 8254 */
#define TIME_PORT_DATA 0x40    /* Data register port for 8254 */
#define TIMER_DIV_CODE 0x36    /* Command code to sent to timer to load divisor */
#define TIME_RATE      1193182 /* The input frequency of the timer (in Hz) */

void connect_timer_to_ioapic(int tick_rate) {
    int interval;

    outb(TIME_PORT_CTRL, TIMER_DIV_CODE);
    interval = TIME_RATE / tick_rate;             // Calculate interrupt interval
    outb(TIME_PORT_DATA, interval & 0xFF);        // Low byte
    outb(TIME_PORT_DATA, (interval >> 8) & 0xFF); // High byte

    /* Remap 8254 timer IRQ to IO-APIC */
    // write_ioapic_reg(TIMER_IRQ_ID, 0x20); // 0x30 vector
}

static void pit_timer_isr(uint8_t num) {

    outb(TIME_PORT_CTRL, 0);
    uint16_t cnt = inb(TIME_PORT_DATA);
    cnt |= inb(TIME_PORT_DATA) << 8;

    printf("called timer int %d: count=%d\n", num, cnt);

    apic_eoi();
    // outb(0x20, 0x20);
}

int ioapic_init() {
    int ret = 0;
    ret = vmm_map_page(s_ioapic, s_ioapic);
    if (ret < 0) {
        return ret;
    }

    interrupts_register(0x20, pit_timer_isr);

    // Map pit IRQ 0 to vector 0x20.
    uint32_t low_offset = IOAPIC_REDTBL + 2 * 0x2;
    uint32_t high_offset = low_offset + 1;
    write_ioapic_reg(low_offset, 0x10000);
    write_ioapic_reg(high_offset, 0);         // Assuming we want the interrupt to go to the first processor
    write_ioapic_reg(low_offset, 0x20 + 0x0); // The 0x20 is a standard offset for hardware interrupts

    connect_timer_to_ioapic(19);
}
