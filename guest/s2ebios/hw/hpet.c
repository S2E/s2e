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

#include <hw/port.h>
#include <inttypes.h>
#include <vmm/vmm.h>

#define HPET_BASE                  0xfed00000
#define HPET_NUMBER_LOWER          0xfed000f0
#define HPET_NUMBER_UPPER          0xfed000f4
#define HPET_GENERAL_CONFIGURATION 0xfed00010
#define HPET_TIMER_CONFIGURATION   0xfed00100
#define HPET_TIMER_COMPARATOR      0xfed00108
#define HPET_TIMER_IRQROUTING      0xfed00110
#define HPET_FREQUENCY             0xfed00004
#define HPET_INTERRUPT_STATUS      0xfed00200
#define HPET_CONFIGURATION_ENABLE  0x1
#define TIMER_CONFIGURATION_ENABLE 0x4
#define INTERRUPT_STATUS_CLEAR     0x1
#define MS_IN_HZ                   1000

#define HPET_ID      0x000
#define HPET_PERIOD  0x004
#define HPET_CFG     0x010
#define HPET_STATUS  0x020
#define HPET_COUNTER 0x0f0

#define HPET_Tn_CFG(n)   (0x100 + 0x20 * n)
#define HPET_Tn_CMP(n)   (0x108 + 0x20 * n)
#define HPET_Tn_ROUTE(n) (0x110 + 0x20 * n)

#define HPET_T0_CFG   0x100
#define HPET_T0_CMP   0x108
#define HPET_T0_ROUTE 0x110
#define HPET_T1_CFG   0x120
#define HPET_T1_CMP   0x128
#define HPET_T1_ROUTE 0x130
#define HPET_T2_CFG   0x140
#define HPET_T2_CMP   0x148
#define HPET_T2_ROUTE 0x150

#define HPET_ID_REV          0x000000ff
#define HPET_ID_NUMBER       0x00001f00
#define HPET_ID_64BIT        0x00002000
#define HPET_ID_LEGSUP       0x00008000
#define HPET_ID_VENDOR       0xffff0000
#define HPET_ID_NUMBER_SHIFT 8
#define HPET_ID_VENDOR_SHIFT 16

#define HPET_CFG_ENABLE  0x001
#define HPET_CFG_LEGACY  0x002
#define HPET_LEGACY_8254 2
#define HPET_LEGACY_RTC  8

#define HPET_TN_LEVEL        0x0002
#define HPET_TN_ENABLE       0x0004
#define HPET_TN_PERIODIC     0x0008
#define HPET_TN_PERIODIC_CAP 0x0010
#define HPET_TN_64BIT_CAP    0x0020
#define HPET_TN_SETVAL       0x0040
#define HPET_TN_32BIT        0x0100
#define HPET_TN_ROUTE        0x3e00
#define HPET_TN_FSB          0x4000
#define HPET_TN_FSB_CAP      0x8000
#define HPET_TN_ROUTE_SHIFT  9

/* Max HPET Period is 10^8 femto sec as in HPET spec */
#define HPET_MAX_PERIOD 100000000UL
/*
 * Min HPET period is 10^5 femto sec just for safety. If it is less than this,
 * then 32 bit HPET counter wrapsaround in less than 0.5 sec.
 */
#define HPET_MIN_PERIOD 100000UL

void hpet_init(void) {
    uint64_t period = 0, tick = 0;

    vmm_map_page(HPET_BASE, HPET_BASE);

    period = mmio_readl(HPET_FREQUENCY);

    // convert period from femtoseconds (10^-15 seconds) to nanoseconds (10^-9 seconds)
    period /= 1000;

    // calculate tick for 10ms, the frequency is expressed in Hz so we need to convert it to MHz first
    tick = (10 * MS_IN_HZ * period) / 1000;

    // enable main counter and legacy replacement route
    mmio_writel(HPET_GENERAL_CONFIGURATION, HPET_CONFIGURATION_ENABLE);

    // clear status register
    mmio_writel(HPET_INTERRUPT_STATUS, INTERRUPT_STATUS_CLEAR);

    // set timer 0 configuration and comparator
    mmio_writel(HPET_TIMER_CONFIGURATION, TIMER_CONFIGURATION_ENABLE);
    mmio_writel(HPET_TIMER_COMPARATOR, tick);
}
