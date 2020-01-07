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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;S2E test - this runs in protected mode
[bits 32]
s2e_test:
    ;call s2e_test_parity
    ;call s2e_test_unaligned_access_symb
    ;call s2e_check_interpreter_symb_helper
    ;call s2e_check_register_write1
    ;call s2e_check_interpreter
    ;call s2e_check_simple_fork

    ;call s2e_symbmem0
    ;call s2e_symbmem1
    ;call s2e_symbmem2
    ;call s2e_symbmem3
    ;call s2e_symbmem4

    call s2e_merge_test

    ;call s2e_test_memspeed
    ;call s2e_sm_test
    ;call s2e_sm_succeed_test
    ;call s2e_test2
    ;call s2e_test_memobj
    ;call s2e_fork_test2
    ;call s2e_symbhwio_test
    ;call fast_jmptbl_test
    ;call test_ndis
    ;jmp s2e_test
    ;call s2e_test1
    ;call s2e_isa_dev
    ;call s2e_bigpage_split
    ;call s2e_test_forced_concretization_in_concolic_mode
    cli
    hlt


;toConstant and toConstantSilent must evaluate the expression
;instead of calling the solver, when running in concolic mode.
;The solver may otherwise return a valid assignment, but that
;contradicts the initial concolic values.
s2e_test_forced_concretization_in_concolic_mode:
    push 0xabcdef
    call s2e_symbolic_int
    add esp, 4

    mov dr7, eax
    cmp eax, 0xabcdef
    ja a1

a1:

    push msg_ok
    push 0
    call s2e_kill_state
    ret

;assertion expression must be a constant here in concolic
;fork sometimes fails because read expression can't be evaluated.
;We need a test case to check that.
;A hypothesis is that it might be caused by symbolic addresses
;in LLVM emulation code...
s2e_test_parity:

    call s2e_int
    add eax, 2
    jp t1
 t1:

    push msg_ok
    push 0
    call s2e_kill_state

    leave
    ret

;Performs an unaligned access at an address
;spanning two pages. The first byte of the second
;page contains a symbolic value
s2e_test_unaligned_access_symb:
    push ebp
    mov ebp, esp

    call s2e_int
    mov [0x4000], eax

    ;Switch to concrete mode
    xor eax, eax
    jmp s2e_ttuas
s2e_ttuas:

    ;Perform the unaligned access
    mov ebx, [0x3fff]

    push ebx
    call s2e_print_expression

    push msg_ok
    push 0
    call s2e_kill_state

    leave
    ret



;Both states are feasible
s2e_concolic_1:
    call s2e_fork_enable

    push 0xdeadbeef
    call s2e_symbolic_int

    cmp eax, 0
    ja sc11

    push msg_ok
    push 0
    call s2e_kill_state
sc11:
    push msg_ok
    push 1
    call s2e_kill_state
    ret


;Check that the engine can
;assign default concrete values in case
;s2e_make_symbolic is used.
s2e_concolic_2:
    call s2e_fork_enable

    call s2e_int

    cmp eax, 0
    ja sc21

    push msg_ok
    push 0
    call s2e_kill_state
sc21:
    push msg_ok
    push 1
    call s2e_kill_state
    ret

bubble_sort:
        push	ebp
        mov	ebp, esp
        sub	esp, 16
L5:
        mov	DWORD  [ebp-4], 0
        mov	DWORD  [ebp-8], 1
        jmp	L2
L4:
        mov	eax, DWORD  [ebp-8]
        sub	eax, 1
        add	eax, DWORD  [ebp+8]
        movzx	edx, BYTE  [eax]
        mov	eax, DWORD  [ebp-8]
        mov	ecx, DWORD  [ebp+8]
        lea	eax, [ecx+eax]
        movzx	eax, BYTE  [eax]
        cmp	dl, al
        jle	L3
        mov	eax, DWORD  [ebp-8]
        sub	eax, 1
        add	eax, DWORD  [ebp+8]
        movzx	eax, BYTE  [eax]
        movsx	eax, al
        mov	DWORD  [ebp-12], eax
        mov	eax, DWORD  [ebp-8]
        sub	eax, 1
        add	eax, DWORD  [ebp+8]
        mov	edx, DWORD  [ebp-8]
        mov	ecx, DWORD  [ebp+8]
        lea	edx, [ecx+edx]
        movzx	edx, BYTE  [edx]
        mov	BYTE  [eax], dl
        mov	eax, DWORD  [ebp-8]
        mov	edx, DWORD  [ebp+8]
        add	edx, eax
        mov	eax, DWORD  [ebp-12]
        mov	BYTE  [edx], al
        mov	DWORD  [ebp-4], 1
L3:
        add	DWORD  [ebp-8], 1
L2:
        mov	eax, DWORD  [ebp-8]
        cmp	eax, DWORD  [ebp+12]
        jb	L4
        cmp	DWORD  [ebp-4], 0
        jne	L5
        leave
        ret


scdf1_start: db "s2e_concolic_disable_start", 0
scdf1_string: db "s2e_concolic_disable_fork done", 0
s2e_concolic_disable_fork:
    push ebp
    mov ebp, esp

    push scdf1_start
    push 0
    call s2e_print_expression

    call s2e_fork_disable
    call s2e_int
    cmp eax, 0
    je  scdf1

scdf1:

    push scdf1_string
    push 0
    call s2e_kill_state
    leave
    ret


%define SORT_STRING_SIZE 25
sort_string: db "This is some text to sort", 0


s2e_concolic_3:
    push ebp
    mov ebp, esp
    sub esp, 0x20*4

    call s2e_fork_enable

    ;Initialize the buffer with the text to sort
    lea edi, [ebp - 0x20*4]
    mov esi, sort_string
    mov ecx, SORT_STRING_SIZE
    cld
    rep movsb

    lea edi, [ebp - 0x20*4]
    push edi
    call s2e_print_message


    lea esi, [ebp - 0x20*4]
    push 0
    push SORT_STRING_SIZE
    push esi
    call s2e_make_symbolic
    add esp, 0x4*3


    ;Do a bubble sort
    lea esi, [ebp - 0x20*4]
    push SORT_STRING_SIZE
    push esi
    call bubble_sort
    add esp, 8

    push esi
    push 0
    call s2e_kill_state

    leave
    ret


s2e_fork_test2:
    push 16
    call s2e_fork_depth
    add esp, 4

    ;Finish the test
    push msg_ok
    push 0
    call s2e_kill_state
    add esp, 8
    ret


;Fork lots of states
s2e_fork_depth:
    push ebp
    mov ebp, esp
    sub esp, 4

    call s2e_fork_enable

    mov eax, dword [ebp + 8]
    mov dword [ebp - 4], eax  ; Set forking depth to eax (2^^eax states)
ssf1:
    call s2e_int
    cmp eax, 0
    ja ssf2
ssf2:
    dec dword [ebp - 4]; Decrement forking depth
    jnz ssf1

    leave
    ret

s2e_test_memspeed:
    mov ecx, 1000000000

lbl1:
    push eax
    pop eax
    dec ecx
    jnz lbl1

    push 0
    push 0
    call s2e_kill_state
    add esp, 8
    ret


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;Testing small memory objects
%define S2E_PAGE_SZE
memok: db "Memory test passed ok", 0
membad: db "MEMORY TEST FAILED", 0
val: db "Value", 0

s2e_test_memobj:
    %push mycontext
    %stacksize flat
    %assign %$localsize 0
    %local root_id:dword, cur_count:dword, obj_bits:dword

    enter %$localsize,0

    mov dword [cur_count], 0

    call s2e_get_path_id
    mov [root_id], eax

    call s2e_get_ram_object_bits
    mov [obj_bits], eax

    ;Create 100 states
  stm0:
    cmp dword [cur_count], 10
    jz stm1

    call s2e_int
    cmp eax, 0
    jz stm1                 ;One state exits the loop
    inc dword [cur_count]   ;The other one continues it
    jmp stm0

  stm1:
    ;In each state, we have a loop that
    ;writes its state id in the page, yields,
    ;checks the content when it gets back the control,
    ;then exits


    call s2e_get_path_id ;Get current path id in eax
    mov edi, 0x100000     ;Start filling at 1MB

    mov ecx, [obj_bits]
    mov edx, 1
    shl edx, cl          ;edx contains the size of the page
    shr edx, 2           ;We want to store dwords

    pusha
    push val
    push edx
    call s2e_print_expression
    add esp, 8
    popa

  stm2:

    ;Fill the memory with the test pattern
    mov ecx, edx
    cld
    rep stosd

    ;Schedule another state
    call s2e_coop_yield

    ;Check that the memory is correct
    mov ecx, edx
    shl ecx, 2
    sub edi, ecx
    mov ecx, edx

  stm3:
    scasd
    loopz stm3
    jnz sterr

    pusha
    push val
    push edi
    call s2e_print_expression
    add esp, 8
    popa

    cmp edi, 0x1000000
    jb stm2

    ;------------------------
    ;Successfully completed the memory test
    push memok
    push 0
    call s2e_kill_state

    ;------------------------
    ;Error during memory check
  sterr:
    push membad
    push edi
    call s2e_kill_state

    leave
    ret



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;Testing I/O with symbolic address/values

s2e_symbhwio_test:
    call s2e_enable

    call s2e_int        ;Get symbolic value
    mov edi, 0xFEC00000 ;APIC address
    mov [edi], eax      ;Write symbolic value to APIC

    mov dx, ax          ;Write to symbolic port a symbolic value
    out dx, ax
ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;Testing enable/disable forking

s2e_fork_test:
    call s2e_enable
    call s2e_fork_enable

    call s2e_int
    cmp eax, 0
    ja sft1

    nop

sft1:

    call s2e_fork_disable
    call s2e_int
    cmp eax, 0
    ja sft2

    nop

sft2:

    push 0
    push 0
    call s2e_kill_state
    add esp, 8

ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;Testing symbolic offsets in jump tables

fast_jmptbl1:
    dd sj0
    dd sj1
    dd sj2
    dd sj3
    dd sj4
    dd sj5
    dd sj6
    dd sj7
    dd sj8
    dd sj9
    dd sj10
    dd sj11
    dd sj12
    dd sj13
    dd sj14
    dd sj15
    dd sj16

fast_jmptbl1_m0: db "Case 0", 0
fast_jmptbl1_m1: db "Case 1", 0
fast_jmptbl1_m2: db "Case 2", 0
fast_jmptbl1_m3: db "Case 3", 0
fast_jmptbl1_m4: db "Case 4", 0
fast_jmptbl1_m5: db "Case 5", 0
fast_jmptbl1_m6: db "Case 6", 0
fast_jmptbl1_m7: db "Case 7", 0
fast_jmptbl1_m8: db "Case 8", 0
fast_jmptbl1_m9: db "Case 9", 0
fast_jmptbl1_m10: db "Case 10", 0
fast_jmptbl1_m11: db "Case 11", 0
fast_jmptbl1_m12: db "Case 12", 0
fast_jmptbl1_m13: db "Case 13", 0
fast_jmptbl1_m14: db "Case 14", 0
fast_jmptbl1_m15: db "Case 15", 0
fast_jmptbl1_m16: db "Case 16", 0
fast_jmptbl1_mdef: db "Default case", 0

fast_jmptbl_test:
    ;XXX: Cannot handle symbolic values in always concrete memory
    ;This is why we need to copy the jump table
    mov esi, fast_jmptbl1
    mov edi, 0x90000
    mov ecx, 17
    cld
    rep movsd

    call s2e_enable

    call s2e_int
    mov esi, fast_jmptbl1_mdef
    cmp eax, 16
    ja sje
    jmp [0x90000 + eax*4]

sj0:
    mov esi, fast_jmptbl1_m0

    ;Write something to the jump table to test
    ;COW for split objects
    ;mov dword [0x90000], 0x123
    mov dword [0x90200], 0x456
    jmp sje

sj1:
    mov esi, fast_jmptbl1_m1
    jmp sje

sj2:
    mov esi, fast_jmptbl1_m2
    jmp sje

sj3:
    mov esi, fast_jmptbl1_m3
    jmp sje

sj4:
    mov esi, fast_jmptbl1_m4
    jmp sje

sj5:
    mov esi, fast_jmptbl1_m5
    jmp sje

sj6:
    mov esi, fast_jmptbl1_m6
    jmp sje

sj7:
    mov esi, fast_jmptbl1_m7
    jmp sje

sj8:
    mov esi, fast_jmptbl1_m8
    jmp sje

sj9:
    mov esi, fast_jmptbl1_m9
    jmp sje

sj10:
    mov esi, fast_jmptbl1_m10
    jmp sje

sj11:
    mov esi, fast_jmptbl1_m11
    jmp sje

sj12:
    mov esi, fast_jmptbl1_m12
    jmp sje

sj13:
    mov esi, fast_jmptbl1_m13
    jmp sje

sj14:
    mov esi, fast_jmptbl1_m14
    jmp sje

sj15:
    mov esi, fast_jmptbl1_m15
    jmp sje

sj16:
    mov esi, fast_jmptbl1_m16
    jmp sje


sje:
    call s2e_disable

    push esi
    push eax
    call s2e_kill_state
    add esp, 8
    ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;Testing symbolic ISA devices
s2e_isa_dev:
    call s2e_enable

isadev1:
    mov dx, 0x100
    in  ax, dx
    cmp ax, 0
    ja isadev1

    jmp isadev1
    call s2e_disable
    call s2e_kill_state
    ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;Testing complicated symbolic expressions
s2e_simplifier1:
    call s2e_enable
    call s2e_int

    ;Testing chains of Zexts
    mov bl, al
    movzx cx, bl
    movzx edx, cx
    cmp edx, 1
    jae ss1

ss1:

    call s2e_disable
    call s2e_kill_state

    ret



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;Testing symbolic memory

;Read a value from a symbolic address in [0;0x10[
;Then write to the first byte
;This tests that accesses that overlap two split pages
;are working properly.
s2e_symbmem0:
    call s2e_int
    cmp eax, 0x10
    jae sm0
        ;Trigger page splitting
        mov ebx, [eax]

        ;Make the first page concrete
        mov ecx, 0x1000
        xor edi, edi
        xor eax, eax
        rep stosb

        ;Switch back to symbex mode
        call s2e_int

        ;Write a value to a concrete address
        ;that overlaps small pages
        mov [127], eax

        ;Check that the value is correct
        cmp eax, [127]
        je sm0

            ;If not, print an error message
            push msg_invalid_val
            push 0
            call s2e_kill_state
            add esp, 8

    sm0:
    push 0
    push 0
    call s2e_kill_state
    add esp, 8
    ret

;Read a value from a symbolic address in [0;0x1000[
s2e_symbmem1:
    call s2e_int
    cmp eax, 0x1000
    jae sm1
        mov ebx, [eax]
    sm1:
    push 0
    push 0
    call s2e_kill_state
    add esp, 8
    ret


;Exercise the case where the concolic value
;leads to an overlapping access at address 126
s2e_symbmem2:
    push 126
    call s2e_symbolic_int
    add esp, 4
    cmp eax, 140
    ja sm2
        mov [eax], eax
        mov ebx, [eax]

        ;Check that the value is correct
        cmp eax, ebx
        je sm2

            ;If not, print an error message
            push msg_invalid_val
            push 0
            call s2e_kill_state
            add esp, 8

    sm2:
    push 0
    push 0
    call s2e_kill_state
    add esp, 8
ret

msg_invalid_val: db "ERROR: Invalid value", 0

s2e_symbmem3:
    push 126
    call s2e_symbolic_int
    add esp, 4
    cmp eax, 4096
    jae sm3
    mov [eax], eax
    mov [eax+4], eax
    mov ebx, [eax]
    mov ecx, [eax+4]
    cmp ebx, ecx
    je sm3
        push msg_invalid_val
        push 0
        call s2e_kill_state
        add esp, 8
    sm3:
    push 0
    push 0
    call s2e_kill_state
    add esp, 8
ret

;Check overlapped access not handle by the softmmu
s2e_symbmem4:
    push 126
    call s2e_symbolic_int
    add esp, 4
    cmp eax, 140
    ja sm4
        ;Split the first memory page
        mov dword [eax], 0
        push eax

        ;Make the first page concrete
        cld
        mov ecx, 0x1000
        xor edi, edi
        xor eax, eax
        rep stosb


        ;Perform overlapped write
        pop eax
        mov dword [eax], 123
        mov ebx, [eax]

        ;Check that the value is correct
        cmp ebx, 123
        je sm4

            ;If not, print an error message
            push msg_invalid_val
            push 0
            call s2e_kill_state
            add esp, 8

    sm4:
    push 0
    push 0
    call s2e_kill_state
    add esp, 8
ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
msg_s2e_int1: db "Called the test handler", 0

s2e_test_int_hdlr:
    push int_msg
    push 0x80
    call s2e_print_expression
    add esp, 8


    ;Access the eflags register
    call s2e_int
    mov edi, [esp + 4]
    test eax, esi

    push 0
    push edi
    call s2e_print_expression
    add esp, 8

    iret

s2e_test_int1:
    ;Register the test interrupt handler
    mov edi, s2e_test_int_hdlr
    mov eax, 0x80
    call add_idt_desc

    ;Starts symbexec
    call s2e_enable
    call s2e_int
    cmp eax, 0
    jz sti_1
    int 0x80
sti_1:
    int 0x80
    call s2e_disable
    call s2e_kill_state
    ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;Infinite loop, without state killing
s2e_test2:
    call s2e_enable
    call s2e_fork_enable
s2etest2_1:
    call s2e_int
    cmp eax, 0
    jz __a
__a:
    jmp s2etest2_1

    ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;Loop that creates symbolic values on each iteration
s2e_test1:

    call s2e_enable

    mov ecx, 0


a:
    push ecx
    call s2e_int
    pop ecx

    ;;Print the counter
    push eax
    push ecx

    push 0
    push ecx
    call s2e_print_expression
    add esp, 8

    pop ecx
    pop eax

    ;;Print the symbolic value
    push eax
    push ecx

    push 0
    push eax
    call s2e_print_expression
    add esp, 8

    pop ecx
    pop eax

    test eax, 1
    jz exit1    ; if (i < symb) exit
    inc ecx
    jmp a

    call s2e_disable
    call s2e_kill_state

    exit1:
    call s2e_disable
    call s2e_kill_state


    ret


msg_ok: db "SUCCESS", 0


s2e_merge_test:
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    mov esi, 0
    mov edi, 32 ; Bit counter

 smt0:
    cmp edi, 0
    jz smt2
    shl esi, 1

    push dword 1
    call s2e_merge_group_begin
    add esp, 4

    call s2e_int
    cmp eax, 0
    je smt1
    or esi, 1
 smt1:

    push dword 1
    call s2e_merge_group_end
    add esp, 4
    dec edi
    jmp smt0

 smt2:
    cmp esi, 0xdeadbeef
    jne smt3
    push 0
    push 3
    call s2e_kill_state
    ret

 smt3:
    push 0
    push 123
    call s2e_kill_state
    ret
