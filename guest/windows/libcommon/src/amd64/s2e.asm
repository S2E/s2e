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

;.amd64                      ; driver's code start
;.model flat, stdcall


.code
public S2EGetVersion
S2EGetVersion proc frame
    .endprolog
    xor rax, rax
    db 0fh, 3fh
    db 00h, 00h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret
S2EGetVersion endp

public S2EGetPathId
S2EGetPathId proc frame
    .endprolog
    xor rax, rax
    db 0fh, 3fh
    db 00h, 05h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret
S2EGetPathId endp

public S2EGetPathCount
S2EGetPathCount proc frame
    .endprolog
    xor rax, rax
    db 0fh, 3fh
    db 00h, 30h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret
S2EGetPathCount endp


;RCX, RDX, R8, R9
public S2EIsSymbolic
S2EIsSymbolic proc frame ; _Buffer: near ptr dword, _Size: dword
    .endprolog
    ;mov rcx, rcx
    mov rax, rdx
    db 0fh, 3fh
    db 00h, 04h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret
S2EIsSymbolic endp

;RCX, RDX, R8, R9
public S2EGetExample
S2EGetExample proc frame ; _Buffer: near ptr dword, _Size: dword
    .endprolog
    mov rax, rcx; _Buffer
    db 0fh, 3fh
    db 00h, 21h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret
S2EGetExample endp

;RCX, RDX, R8, R9
public S2EGetRange
S2EGetRange proc frame ; _Expr: dword, _Low: near ptr dword, _High: near ptr dword
    .endprolog
    mov rax, rcx ; rax = _Expr
    mov rcx, rdx; rcx = _Low
    mov rdx, r8; rdx = _High
    db 0fh, 3fh
    db 00h, 34h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret
S2EGetRange endp

;RCX, RDX, R8, R9
public S2EGetConstraintCount
S2EGetConstraintCount proc frame ; _Expr: dword
    .endprolog
    mov rax, rcx ; rax = _Expr
    db 0fh, 3fh
    db 00h, 35h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret
S2EGetConstraintCount endp

;RCX, RDX, R8, R9
public S2EConcretize
S2EConcretize proc frame ; _Buffer: near ptr dword, _Size: dword
    .endprolog
    mov rax, rcx  ; _Buffer
    ;mov edx, edx ; _Size
    db 0fh, 3fh
    db 00h, 20h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret
S2EConcretize endp


;RCX, RDX, R8, R9
public S2EMakeSymbolicRaw
S2EMakeSymbolicRaw proc frame ; _Buffer: near ptr dword, _Size: dword, _Name: near ptr dword
    push rbx
    .pushreg rbx
    .endprolog
    mov rax, rcx
    mov ebx, edx
    mov rcx, r8
    db 0fh, 3fh
    db 00h, 03h, 00h, 00h
    db 00h, 00h, 00h, 00h
    pop rbx
    ret
S2EMakeSymbolicRaw endp


;RCX, RDX, R8, R9
public S2EHexDump
S2EHexDump proc frame ; _Name: near ptr dword, _Buffer: near ptr dword, _Size: dword
    push rbx
    .pushreg rbx
    .endprolog
    mov rax, rdx
    mov ebx, r8d
    db 0fh, 3fh
    db 00h, 36h, 00h, 00h
    db 00h, 00h, 00h, 00h
    pop rbx
    ret
S2EHexDump endp

public S2EBeginAtomic
S2EBeginAtomic proc frame
    .endprolog
    nop
    db 0fh, 3fh
    db 00h, 12h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret
S2EBeginAtomic endp

public S2EEndAtomic
S2EEndAtomic proc frame
    .endprolog
    nop
    db 0fh, 3fh
    db 00h, 13h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret
S2EEndAtomic endp

public S2EAssume
S2EAssume proc frame ;_Expression: dword
    .endprolog
    xor rax, rax
    mov eax, ecx;_Expression
    db 0fh, 3fh
    db 00h, 0ch, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret
S2EAssume endp


public S2EMessageRaw
S2EMessageRaw proc frame ;, _Message: near ptr dword
    .endprolog
    mov rax, rcx ;_Message
    db 0fh, 3fh
    db 00h, 10h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret
S2EMessageRaw endp

;Transmits a buffer of dataSize length to the plugin named in pluginName.
;eax contains the failure code upon return, 0 for success.
;RCX, RDX, R8, R9
public S2EInvokePluginRaw
S2EInvokePluginRaw proc frame ; _PluginName: near ptr dword, _UserData: near ptr dword, _DataSize: dword
    .endprolog

    mov rax, rcx; _PluginName
    mov rcx, rdx; _UserData
    mov edx, r8d; _DataSize
    db 0fh, 3fh
    db 00h, 0bh, 00h, 00h
    db 00h, 00h, 00h, 00h

    ret
S2EInvokePluginRaw endp

;Transmits a buffer of dataSize length to the plugin named in pluginName.
;eax contains the failure code upon return, 0 for success.
;RCX, RDX, R8, R9
public S2EInvokePluginConcreteModeRaw
S2EInvokePluginConcreteModeRaw proc frame ; _PluginName: near ptr dword, _UserData: near ptr dword, _DataSize: dword
    .endprolog

    mov rax, rcx; _PluginName
    mov rcx, rdx; _UserData
    mov edx, r8d; _DataSize

    push rbx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    xor rbx, rbx
    xor rsi, rsi
    xor rdi, rdi
    xor rbp, rbp
    xor r9, r9
    xor r10, r10
    xor r11, r11
    xor r12, r12
    xor r13, r13
    xor r14, r14
    xor r15, r15

    ;Clear temp flags
    db 0fh, 3fh
    db 00h, 53h, 00h, 00h
    db 00h, 00h, 00h, 00h

    jmp __sipcmr ;Ensure switch to concrete mode
 __sipcmr:

    db 0fh, 3fh
    db 00h, 0bh, 00h, 00h
    db 00h, 00h, 00h, 00h

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rbx

    ret
S2EInvokePluginConcreteModeRaw endp

; Add a constraint of the form var == e1 || var == e2 || ...
; The first parameter contains the variable
; The second parameter has the number of passed expressions
; XXX: fix the plugin for amd64 calling convention
public S2EAssumeDisjunction
S2EAssumeDisjunction proc frame ; _Variable: dword, _Count: dword, _Expressions: vararg
    ;Spill arguments to the stack
    mov [rsp + 08h], rcx
    mov [rsp + 10h], rdx
    mov [rsp + 18h], r8
    mov [rsp + 20h], r9
    push rbp     ;Dummy push to satisfy the custom instruction handler
    .pushreg rbp
    .endprolog
    db 0fh, 3fh
    db 00h, 0dh, 00h, 00h
    db 00h, 00h, 00h, 00h
    pop rbp
    ret
S2EAssumeDisjunction endp

public S2EKillState
S2EKillState proc frame ;, _Status: near ptr dword, _Message: near ptr dword
    push rbx
    .pushreg rbx
    .endprolog
    mov rax, rcx ;_Status
    mov rbx, rdx ;_Message
    db 0fh, 3fh
    db 00h, 06h, 00h, 00h
    db 00h, 00h, 00h, 00h
    pop rbx
    ret
S2EKillState endp

public S2EPrintExpression
S2EPrintExpression proc frame; , _Expression: near ptr dword, _Name: near ptr dword
    .endprolog
    mov rax, rcx; _Expression
    mov rcx, rdx; _Name
    db 0fh, 3fh
    db 00h, 07h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret
S2EPrintExpression endp

public S2EWriteMemory
S2EWriteMemory proc frame; _Dest: near ptr dword, _Source: near ptr dword, _Size: near dword
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    .endprolog
    mov rsi, rdx ; _Source
    mov rdi, rcx; _Dest
    mov ecx, r8d; _Size
    db 0fh, 3fh
    db 00h, 33h, 00h, 00h
    db 00h, 00h, 00h, 00h
    pop rdi
    pop rsi
    ret
S2EWriteMemory endp

__MergingSearcher db "MergingSearcher", 0

;Can't be any interrupts in there
public S2EMergePointCallback
S2EMergePointCallback proc frame
    .endprolog
    pushfq
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rsp
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    sub rsp, 8

    ;Setup the start variable (set to 0)
    xor rax, rax
    mov [rsp], rax
    lea rax, [esp]

    ;Invoke the merging searcher
    lea rcx, __MergingSearcher
    mov rdx, rax; data pointer
    mov r8d, 8 ; data size
    sub rsp, 4 * 8; amd64 calling convention
    call S2EInvokePluginConcreteModeRaw

    call S2EEnableAllApicInterrupts
    add rsp, 4 * 8

    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rsp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    popfq
    ret
S2EMergePointCallback endp

public S2EDisableAllApicInterrupts
S2EDisableAllApicInterrupts proc frame
    .endprolog
    xor rax, rax
    db 0fh, 3fh
    db 00h, 51h, 01h, 00h
    db 00h, 00h, 00h, 00h
    ret
S2EDisableAllApicInterrupts endp

public S2EEnableAllApicInterrupts
S2EEnableAllApicInterrupts proc frame
    .endprolog
    xor rax, rax
    db 0fh, 3fh
    db 00h, 51h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret
S2EEnableAllApicInterrupts endp

public S2EReturnHook64
S2EReturnHook64 proc frame
    .endprolog
    add rsp, 11 * 8 ;point to the return address of the caller
    ret
S2EReturnHook64 endp

end
