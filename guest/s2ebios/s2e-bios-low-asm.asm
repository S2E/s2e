; S2E Selective Symbolic Execution Platform
;
; Copyright (c) 2013 Dependable Systems Laboratory, EPFL
;
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
;
; The above copyright notice and this permission notice shall be included in all
; copies or substantial portions of the Software.
;
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
; SOFTWARE.

;This is the lower part of the bios, at 0xe0000
;It runs in protected mode

[bits 32]

%define OSDATA32_SEL  0x08
%define OSCODE32_SEL  0x10

org 0xe0000

jmp start
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;Interrupt descriptor table
%define IDT_START   0
pm_idtr:
                dw 0x8*256
                dd IDT_START

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%define IA32_IDT_TYPE_32BITS 0x0800
%define IA32_IDT_PRESENT 0x8000

;On initialise le PIC 8259A...
pmode_initpic:
MOV AL,00010001b
OUT 0x20,AL                  ;ICW1 - MASTER
OUT 0xA0,AL                  ;ICW1 - SLAVE
MOV AL,20h
OUT 0x21,AL                  ;ICW2 - MASTER
MOV AL,28h
OUT 0xa1,AL                  ;ICW2 - SLAVE
MOV AL,00000100b
OUT 0x21,AL                  ;ICW3 - MASTER
MOV AL,00000010b
OUT 0xa1,AL                  ;ICW3 - SLAVE
MOV AL,00000001b
OUT 0x21,AL                  ;ICW4 - MASTER
OUT 0xa1,AL                  ;ICW4 - SLAVE
MOV AL,11111011b			;Masked all but cascade/timer
OUT 0x21,AL                  ;MASK - MASTER (0= Ints ON)
MOV AL,11111111b
OUT 0xa1,AL                  ;MASK - SLAVE
RET


;eax: interrupt number
;edi: handler
msg_add_idt: db "Adding interrupt vector ", 0
add_idt_desc:
    push edi
    shl eax, 3
    add eax, IDT_START

    mov [eax], di
    mov word [eax+2], OSCODE32_SEL
    mov word [eax+4], IA32_IDT_PRESENT | IA32_IDT_TYPE_32BITS | 0x0600
    shr edi, 16
    mov [eax+6], di
    pop edi
    ret

start:

    ;Initialize interrupt tables here
    push msg_init_int_table
    call s2e_print_message
    add esp, 4

    xor ecx, ecx
    mov edi, int_default

start_0:
    cmp ecx, 256
    jae start_1

    ;push ecx
    ;push msg_add_idt
    ;push ecx
    ;call s2e_print_expression
    ;add esp, 8
    ;pop ecx

    push ecx
    mov eax, ecx
    call add_idt_desc
    pop ecx
    inc ecx
    jmp start_0

start_1:

    mov eax, 0
    mov edi, int_0
    call add_idt_desc

    lidt [pm_idtr]

    call pmode_initpic
    sti

    ; Test an interrupt call
    ;int 0x80

    ;cli
    ;hlt

    ; Go to the testing routines
    jmp s2e_test

%include "s2e-inst.asm"
%include "s2e-test.asm"

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;Interrupt handlers
msg_init_int_table: db "Initializing interrupt table", 0
int_msg_default: db "Called default interrupt handler", 0
int_div_zero: db "Division by zero", 0
int_msg: db "Called interrupt", 0

; Default interrupt handler
int_default:
    pusha
    push int_msg_default
    call s2e_print_message
    add esp, 4
    popa
    iret

; Default interrupt handler
int_0:
    pusha
    push int_div_zero
    push 0
    call s2e_kill_state
    add esp, 4
    popa
    iret

int80:
    push int_msg
    push 0x80
    call s2e_print_expression
    add esp, 8

iret


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


times 0x10000 - ($-$$) db 0

