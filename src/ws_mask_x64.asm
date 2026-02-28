OPTION CASEMAP:NONE

_TEXT SEGMENT

PUBLIC ws_mask_xor_copy_x64
; void ws_mask_xor_copy_x64(uint8_t* dst, const uint8_t* src, uint64_t len, uint32_t mask32)
; rcx=dst, rdx=src, r8=len, r9d=mask32
ws_mask_xor_copy_x64 PROC
    test r8, r8
    jz  copy_done

    mov r10d, r9d
    mov r11d, r9d
    shl r11, 32
    or  r10, r11

copy_qword_loop:
    cmp r8, 8
    jb  copy_tail
    mov rax, QWORD PTR [rdx]
    xor rax, r10
    mov QWORD PTR [rcx], rax
    add rdx, 8
    add rcx, 8
    sub r8, 8
    jmp copy_qword_loop

copy_tail:
    mov r10d, r9d
copy_tail_loop:
    test r8, r8
    jz   copy_done
    mov  al, BYTE PTR [rdx]
    xor  al, r10b
    mov  BYTE PTR [rcx], al
    inc  rdx
    inc  rcx
    ror  r10d, 8
    dec  r8
    jmp  copy_tail_loop

copy_done:
    ret
ws_mask_xor_copy_x64 ENDP

PUBLIC ws_mask_xor_inplace_x64
; void ws_mask_xor_inplace_x64(uint8_t* buf, uint64_t len, uint32_t mask32)
; rcx=buf, rdx=len, r8d=mask32
ws_mask_xor_inplace_x64 PROC
    test rdx, rdx
    jz   inpl_done

    mov r9d, r8d
    mov r10d, r8d
    shl r10, 32
    or  r9, r10

inpl_qword_loop:
    cmp rdx, 8
    jb  inpl_tail
    mov rax, QWORD PTR [rcx]
    xor rax, r9
    mov QWORD PTR [rcx], rax
    add rcx, 8
    sub rdx, 8
    jmp inpl_qword_loop

inpl_tail:
    mov r9d, r8d
inpl_tail_loop:
    test rdx, rdx
    jz   inpl_done
    mov  al, BYTE PTR [rcx]
    xor  al, r9b
    mov  BYTE PTR [rcx], al
    inc  rcx
    ror  r9d, 8
    dec  rdx
    jmp  inpl_tail_loop

inpl_done:
    ret
ws_mask_xor_inplace_x64 ENDP

_TEXT ENDS
END
