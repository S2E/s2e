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

%include "init.asm"

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


times 0x10000 - 16 - ($-$$) db 0

;0xf000:fff0
boot:
jmp 0xf000:start

times 0x10000-($-$$) db 0
