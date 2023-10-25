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
global test_memory_rw_new_page
global test_memory_rw_same_page_unaligned
global test_memory_rw_same_page_unaligned_signed

s2e_kill_state:
    push rbp
    mov rbp, rsp
    push rbx

    mov rbx, [rbp + 0x18] ;message
    mov rax, [rbp + 0x10] ;status

    db 0x0f
    db 0x3f ; S2EOP

    db 0x00 ; Built-in instructions
    db 0x06 ; Kill the current state
    db 0x00
    db 0x00
    dd 0x0

    pop rbx
    leave
    ret

test_memory_rw_new_page:
    push    rbp
    mov     rbp, rsp

    ; 1 byte rw
    mov al, 0xdf
    mov rcx, 0x20000
    mov [rcx], al
    mov dl, [rcx]
    cmp dl, al
    jne tmrnp1_bad

    ; 2 bytes rw
    mov ax, 0x12df
    mov rcx, 0x21000
    mov [rcx], ax
    mov dx, [rcx]
    cmp dx, ax
    jne tmrnp1_bad

    ; 4 bytes rw
    mov eax, 0x212312df
    mov rcx, 0x23000
    mov [rcx], eax
    mov edx, [rcx]
    cmp edx, eax
    jne tmrnp1_bad

    ; 8 bytes rw
    mov rax, 0x12df2233deadbeef
    mov rcx, 0x24000
    mov [rcx], rax
    mov rdx, [rcx]
    cmp rdx, rax
    jne tmrnp1_bad

    jmp tmrnp1_end
tmrnp1_bad:
    push msg_bad
    push 0
    call s2e_kill_state

tmrnp1_end:
    leave
    ret


test_memory_rw_same_page_unaligned:
    push    rbp
    mov     rbp, rsp

    ; 2 bytes rw
    mov ax, 0x12df
    mov rcx, 0x21001
    mov [rcx], ax
    mov dx, [rcx]
    cmp dx, ax
    jne tmrspu_bad

    ; 4 bytes rw
    mov eax, 0x12df2233
    mov rcx, 0x23001
    mov [rcx], eax
    mov edx, [rcx]
    cmp edx, eax
    jne tmrspu_bad

    ; 8 bytes rw
    mov rax, 0x12df1234deadbeef
    mov rcx, 0x24001
    mov [rcx], rax
    mov rdx, [rcx]
    cmp rdx, rax
    jne tmrspu_bad

    jmp tmrspu_end
tmrspu_bad:
    push msg_bad
    push 0
    call s2e_kill_state

tmrspu_end:
    leave
    ret


test_memory_rw_same_page_unaligned_signed:
    push    rbp
    mov     rbp, rsp

    ; 2 bytes rw
    mov ax, 0x82df
    mov rcx, 0x21001
    mov [rcx], ax
    movsx edx, word [rcx]
    cmp edx, 0xffff82df
    jne tmrspus_bad

    ; 4 bytes rw
    mov eax, 0x82df2233
    mov rcx, 0x23001
    mov [rcx], eax
    movsx rdx, dword [rcx]
    cmp rdx, 0xffffffff82df2233
    jne tmrspus_bad
   
    jmp tmrspus_end
tmrspus_bad:
    push msg_bad
    push 0
    call s2e_kill_state

tmrspus_end:
    leave
    ret


msg_bad: db "BAD", 0
