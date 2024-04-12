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

.386                      ; driver's code start
.model flat, stdcall


.code
public S2EGetVersion
S2EGetVersion proc near
    xor eax, eax
    db 0fh, 3fh
    db 00h, 00h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret
S2EGetVersion endp

.code
public S2EGetPathId
S2EGetPathId proc near
    xor eax, eax
    db 0fh, 3fh
    db 00h, 05h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret
S2EGetPathId endp

public S2EGetPathCount
S2EGetPathCount proc near
    xor eax, eax
    db 0fh, 3fh
    db 00h, 30h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret
S2EGetPathCount endp


public S2EIsSymbolic
S2EIsSymbolic proc near _Buffer: near ptr dword, _Size: dword
    mov ecx, _Buffer
    mov eax, _Size
    db 0fh, 3fh
    db 00h, 04h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret 08h
S2EIsSymbolic endp

public S2EGetExample
S2EGetExample proc near _Buffer: near ptr dword, _Size: dword
    mov eax, _Buffer
    mov edx, _Size
    db 0fh, 3fh
    db 00h, 21h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret 08h
S2EGetExample endp

public S2EGetRange
S2EGetRange proc near _Expr: dword, _Low: near ptr dword, _High: near ptr dword
    mov eax, _Expr
    mov ecx, _Low
    mov edx, _High
    db 0fh, 3fh
    db 00h, 34h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret 0ch
S2EGetRange endp

public S2EGetConstraintCount
S2EGetConstraintCount proc near _Expr: dword
    mov eax, _Expr
    db 0fh, 3fh
    db 00h, 35h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret 04h
S2EGetConstraintCount endp

public S2EConcretize
S2EConcretize proc near _Buffer: near ptr dword, _Size: dword
    mov eax, _Buffer
    mov edx, _Size
    db 0fh, 3fh
    db 00h, 20h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret 08h
S2EConcretize endp

public S2EMakeSymbolicRaw
S2EMakeSymbolicRaw proc near uses ebx, _Buffer: near ptr dword, _Size: dword, _Name: near ptr dword
    push ebx
    mov eax, _Buffer
    mov ebx, _Size
    mov ecx, _Name
    db 0fh, 3fh
    db 00h, 03h, 00h, 00h
    db 00h, 00h, 00h, 00h
    pop ebx
    ret 0ch
S2EMakeSymbolicRaw endp

public S2EHexDump
S2EHexDump proc near uses ebx, _Name: near ptr dword, _Buffer: near ptr dword, _Size: dword
    push ebx
    mov eax, _Buffer
    mov ebx, _Size
    mov ecx, _Name
    db 0fh, 3fh
    db 00h, 36h, 00h, 00h
    db 00h, 00h, 00h, 00h
    pop ebx
    ret 0ch
S2EHexDump endp

public S2EBeginAtomic
S2EBeginAtomic proc near
    nop
    db 0fh, 3fh
    db 00h, 12h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret
S2EBeginAtomic endp

public S2EEndAtomic
S2EEndAtomic proc near
    nop
    db 0fh, 3fh
    db 00h, 13h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret
S2EEndAtomic endp

public S2EAssume
S2EAssume proc near, _Expression: dword
    mov eax, _Expression
    db 0fh, 3fh
    db 00h, 0ch, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret 4h
S2EAssume endp


public S2EMessageRaw
S2EMessageRaw proc near, _Message: near ptr dword
    mov eax, _Message
    db 0fh, 3fh
    db 00h, 10h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret 4h
S2EMessageRaw endp

;Transmits a buffer of dataSize length to the plugin named in pluginName.
;eax contains the failure code upon return, 0 for success.
public S2EInvokePluginRaw
S2EInvokePluginRaw proc near, _PluginName: near ptr dword, _UserData: near ptr dword, _DataSize: dword
    mov eax, _PluginName
    mov ecx, _UserData
    mov edx, _DataSize
    db 0fh, 3fh
    db 00h, 0bh, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret 0ch
S2EInvokePluginRaw endp

;Transmits a buffer of dataSize length to the plugin named in pluginName.
;Sets all registers to a concrete value to ensure concrete mode
;eax contains the failure code upon return, 0 for success.
public S2EInvokePluginConcreteModeRaw
S2EInvokePluginConcreteModeRaw proc near, _PluginName: near ptr dword, _UserData: near ptr dword, _DataSize: dword
    mov eax, _PluginName
    mov ecx, _UserData
    mov edx, _DataSize

    push ebx
    push ebp
    push esi
    push edi
    xor ebx, ebx
    xor ebp, ebp
    xor esi, esi
    xor edi, edi

    ;Clear temp flags
    db 0fh, 3fh
    db 00h, 53h, 00h, 00h
    db 00h, 00h, 00h, 00h

    jmp __sipcmr ;Ensure switch to concrete mode
 __sipcmr:
    db 0fh, 3fh
    db 00h, 0bh, 00h, 00h
    db 00h, 00h, 00h, 00h

    pop edi
    pop esi
    pop ebp
    pop ebx

    ret 0ch
S2EInvokePluginConcreteModeRaw endp

; Add a constraint of the form var == e1 || var == e2 || ...
; The first parameter contains the variable
; The second parameter has the number of passed expressions
public S2EAssumeDisjunction
S2EAssumeDisjunction proc c, _Variable: dword, _Count: dword, _Expressions: vararg
    mov eax, _Variable    ;Dummy moves to supress unused variable
    mov eax, _Count
    mov eax, _Expressions
    db 0fh, 3fh
    db 00h, 0dh, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret
S2EAssumeDisjunction endp

public S2EKillState
S2EKillState proc near, _Status: near ptr dword, _Message: near ptr dword
    push ebx
    mov eax, _Status
    mov ebx, _Message
    db 0fh, 3fh
    db 00h, 06h, 00h, 00h
    db 00h, 00h, 00h, 00h
    pop ebx
    ret 08h
S2EKillState endp

public S2EPrintExpression
S2EPrintExpression proc near, _Expression: near ptr dword, _Name: near ptr dword
    mov eax, _Expression
    mov ecx, _Name
    db 0fh, 3fh
    db 00h, 07h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret 08h
S2EPrintExpression endp

public S2EWriteMemory
S2EWriteMemory proc near, _Dest: near ptr dword, _Source: near ptr dword, _Size: dword
    push esi
    push edi
    mov esi, _Source
    mov edi, _Dest
    mov ecx, _Size
    db 0fh, 3fh
    db 00h, 33h, 00h, 00h
    db 00h, 00h, 00h, 00h
    pop edi
    pop esi
    ret 0ch
S2EWriteMemory endp

__MergingSearcher db "MergingSearcher", 0

public S2EMergePointCallback
S2EMergePointCallback proc near
    pushfd
    pusha
    sub esp, 8

    ;Setup the start variable (set to 0)
    xor eax, eax
    mov [esp], eax
    mov [esp+4], eax
    lea eax, [esp]

    ;Invoke the merging searcher
    push 8 ; data size
    push eax; data pointer
    push dword ptr __MergingSearcher
    call S2EInvokePluginConcreteModeRaw

    call S2EEnableAllApicInterrupts

    ;Cleanup the mess and return
    add esp, 8
    popa
    popfd
    ret
S2EMergePointCallback endp

public S2EDisableAllApicInterrupts
S2EDisableAllApicInterrupts proc near
    xor eax, eax
    db 0fh, 3fh
    db 00h, 51h, 01h, 00h
    db 00h, 00h, 00h, 00h
    ret
S2EDisableAllApicInterrupts endp

public S2EEnableAllApicInterrupts
S2EEnableAllApicInterrupts proc near
    xor eax, eax
    db 0fh, 3fh
    db 00h, 51h, 00h, 00h
    db 00h, 00h, 00h, 00h
    ret
S2EEnableAllApicInterrupts endp

end

