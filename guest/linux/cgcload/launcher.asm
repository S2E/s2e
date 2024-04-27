section .text
global launch_binary         ; Make the function global for linking from C.


; Initialize the execution environment and launch the binary.
; Set register values according to specification of the CGC ABI:
; https://github.com/CyberGrandChallenge/libcgc/blob/master/cgcabi.md
;
; Function declaration with parameters:
; void launch_binary(uintptr_t stack, uintptr_t magic, cgc_main_t entry)
launch_binary:
    push ebp                 ; Save old base pointer
    mov ebp, esp             ; Set base pointer to current stack pointer

    ; Arguments are right above the saved EBP on the stack:
    ; ebp + 8 -> stack
    ; ebp + 12 -> magic
    ; ebp + 16 -> entry

    ; Set up the stack pointer (ESP)
    mov eax, [ebp + 8]       ; Load 'stack' argument into eax
    sub eax, 4               ; Adjust 'stack' by subtracting 4
    mov esp, eax             ; Set 'stack' as the new stack pointer

    ; Set up other registers according to the specification
    mov ecx, [ebp + 12]      ; Load 'magic' into ECX
    mov eax, [ebp + 16]      ; Load 'entry' function pointer into EAX

    xor ebx, ebx             ; Zero out EBX
    xor edx, edx             ; Zero out EDX
    xor edi, edi             ; Zero out EDI
    xor esi, esi             ; Zero out ESI
    xor ebp, ebp             ; Zero out EBP

    ; Set up flags register with specific flags (bit 9 - IF, Interrupt Enable Flag)
    push dword 0x202         ; Push 0x202 onto the stack
    popfd                    ; Pop it into EFLAGS, setting specific flags

    ; Call the function pointer in EAX
    call eax                 ; Call 'entry'

    ; Restore the previous stack frame
    pop ebp                  ; Restore the old base pointer
    ret                      ; Return from the function

section .note.GNU-stack noalloc noexec nowrite
