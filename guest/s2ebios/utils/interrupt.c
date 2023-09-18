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
#include <s2e/s2e.h>

#include "interrupt.h"

static void lidt(void *base, uint16_t size) {
    struct {
        uint16_t length;
        void *base;
    } __attribute__((packed)) IDTR = {size, base};

    __asm__ volatile("lidt %0" : : "m"(IDTR));
}

static void sti() {
    __asm__ volatile("sti");
}

void isr_handler();

#define IDT_SIZE 256

typedef struct {
    uint16_t offset_1;  // offset bits 0..15
    uint16_t selector;  // a code segment selector in GDT or LDT
    uint8_t zero;       // unused, set to 0
    uint8_t type_attr;  // type and attributes
    uint16_t offset_2;  // offset bits 16..31
    uint32_t offset_3;  // offset bits 32..63
    uint32_t zero_long; // reserved
} __attribute__((packed)) idt_entry64_t;

static idt_entry64_t s_idt[IDT_SIZE];
static isr_t s_isrs[IDT_SIZE];

extern uintptr_t *isr_handlers_ptr;

void isr_handler_c(uint8_t i) {
    if (s_isrs[i]) {
        s_isrs[i](i);
    } else {
        s2e_kill_state(i, "called spurious int");
    }
}

int interrupts_register(uint8_t num, isr_t isr) {
    if (s_isrs[num]) {
        return -1;
    }

    s_isrs[num] = isr;
    return 0;
}

// TODO: 32-bit code
static void interrupts_map(unsigned i, uintptr_t handler) {
    s_idt[i].offset_1 = (uint64_t) handler & 0xFFFF;
    s_idt[i].selector = 0x08;  // our kernel code segment
    s_idt[i].type_attr = 0x8E; // Interupt gate, and a Present bit.
    s_idt[i].offset_2 = ((uint64_t) handler >> 16) & 0xFFFF;
    s_idt[i].offset_3 = (uint64_t) handler >> 32;
    s_idt[i].zero = 0;
    s_idt[i].zero_long = 0;
}

void interrupts_init(void) {
    for (int i = 0; i < IDT_SIZE; i++) {
        interrupts_map(i, isr_handlers_ptr[i]);
    }

    lidt(&s_idt, sizeof(s_idt));
    sti();
}
