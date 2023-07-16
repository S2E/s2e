; S2E Selective Symbolic Execution Platform
;
; Copyright (c) 2023 Vitaly Chipounov
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


section .text
extern isr_handler_c
global isr_handlers_ptr

%macro ISR_HANDLER 1
isr_handler_%1:
    pusha
    pushfd

    mov eax, %1
    push eax
    extern isr_handler_c
    call isr_handler_c
    add esp, 4

    popfd
    popa
    iretd
%endmacro

%macro ISR_HANDLER_DECL 1
    dd isr_handler_%1
%endmacro

%assign i 0
%rep 256
    ISR_HANDLER i
    %assign i i+1
%endrep

isr_handlers:
%assign i 0
%rep 256
    ISR_HANDLER_DECL i
    %assign i i+1
%endrep

isr_handlers_ptr dd isr_handlers