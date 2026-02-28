OPTION CASEMAP:NONE

; funasr_ctx_x64_t layout (bytes):
;   0  rsp
;   8  rbx
;   16 rbp
;   24 rsi
;   32 rdi
;   40 r12
;   48 r13
;   56 r14
;   64 r15
;   72 rip

_TEXT SEGMENT

PUBLIC funasr_ctx_switch_x64
; void funasr_ctx_switch_x64(funasr_ctx_x64_t* from, const funasr_ctx_x64_t* to)
; rcx=from, rdx=to
funasr_ctx_switch_x64 PROC
    ; Save current callee-saved state to *from.
    lea rax, [rsp + 8]
    mov [rcx + 0],  rax
    mov [rcx + 8],  rbx
    mov [rcx + 16], rbp
    mov [rcx + 24], rsi
    mov [rcx + 32], rdi
    mov [rcx + 40], r12
    mov [rcx + 48], r13
    mov [rcx + 56], r14
    mov [rcx + 64], r15
    mov rax, [rsp]
    mov [rcx + 72], rax

    ; Restore target context from *to and jump to saved RIP.
    mov rsp, [rdx + 0]
    mov rbx, [rdx + 8]
    mov rbp, [rdx + 16]
    mov rsi, [rdx + 24]
    mov rdi, [rdx + 32]
    mov r12, [rdx + 40]
    mov r13, [rdx + 48]
    mov r14, [rdx + 56]
    mov r15, [rdx + 64]
    mov rax, [rdx + 72]
    jmp rax
funasr_ctx_switch_x64 ENDP

_TEXT ENDS
END
