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

;Assemble this file to a raw binary, and specify it as the BIOS
;This binary will be loaded at 0xf0000

org 0

[bits 16]
start:
    cli
    mov ax, cs
    mov ds, ax
    mov ax, 0x8000
    mov ss, ax
    mov sp, 0
    call init_pmode

    cli
    hlt

[bits 16]

;Quick and dirty pmode init
%define SEGMENT_COUNT 3
%define OSDATA32_SEL  0x08
%define OSCODE32_SEL  0x10

pm_nullseg:
        dd 0
        dd 0
pm_dataseg:
        dw 0xFFFF	;Seg limit
        dw 0x0000	;Base
        db 0x0	;base
        db 0x80 + 0x10 + 2 ;Present+code or data + RW data
        db 0x80 + 0x40 + 0xF; Granularity+32bits + limit
        db 0

pm_codeseg:
        dw 0xFFFF	;Seg limit
        dw 0	;Base
        db 0x0	;base
        db 0x80 + 0x10 + 10 ;Present+code or data + Exec/RO
        db 0x80 + 0x40 + 0xF; Granularity+32bits + limit
        db 0

;GDTR value
pm_gdtr:
        dw 0x8*SEGMENT_COUNT
pm_gdtraddr	dd 0xF0000 + pm_nullseg

init_pmode:

    cli
    lgdt [pm_gdtr]
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    db 66h
    db 67h
    db 0xEA
    dd init_pmode2+0xf0000
    dw OSCODE32_SEL
    hlt

[bits 32]
init_pmode2:
    mov eax, OSDATA32_SEL
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov esp, 0x80000
    mov eax, 0xe0000
    call eax
    cli    
    hlt


times 0x10000 - 16 - ($-$$) db 0

;0xf000:fff0
boot:
jmp 0xf000:start

times 0x10000-($-$$) db 0
