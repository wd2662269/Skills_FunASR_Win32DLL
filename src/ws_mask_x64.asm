OPTION CASEMAP:NONE

_TEXT SEGMENT

PUBLIC ws_mask_xor_copy_x64
PUBLIC ws_mask_xor_copy_avx2_x64
; void ws_mask_xor_copy_x64(uint8_t* dst, const uint8_t* src, uint64_t len, uint32_t mask32)
; rcx=dst, rdx=src, r8=len, r9d=mask32
ws_mask_xor_copy_x64 PROC
    test r8, r8
    jz  copy_done

    movd xmm0, r9d
    pshufd xmm0, xmm0, 0

copy_xmm_loop:
    cmp r8, 16
    jb  copy_qword_loop
    movdqu xmm1, XMMWORD PTR [rdx]
    pxor xmm1, xmm0
    movdqu XMMWORD PTR [rcx], xmm1
    add rdx, 16
    add rcx, 16
    sub r8, 16
    jmp copy_xmm_loop

copy_qword_loop:
    cmp r8, 8
    jb  copy_tail
    mov r10d, r9d
    mov r11d, r9d
    shl r11, 32
    or  r10, r11
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

; void ws_mask_xor_copy_avx2_x64(uint8_t* dst, const uint8_t* src, uint64_t len, uint32_t mask32)
; rcx=dst, rdx=src, r8=len, r9d=mask32
ws_mask_xor_copy_avx2_x64 PROC
    test r8, r8
    jz  copy_avx2_done

    vmovd xmm0, r9d
    vpbroadcastd ymm0, xmm0

copy_avx2_loop:
    cmp r8, 32
    jb  copy_avx2_tail
    vmovdqu ymm1, YMMWORD PTR [rdx]
    vpxor ymm1, ymm1, ymm0
    vmovdqu YMMWORD PTR [rcx], ymm1
    add rdx, 32
    add rcx, 32
    sub r8, 32
    jmp copy_avx2_loop

copy_avx2_tail:
    vzeroupper
    test r8, r8
    jz   copy_avx2_done
    jmp  ws_mask_xor_copy_x64

copy_avx2_done:
    vzeroupper
    ret
ws_mask_xor_copy_avx2_x64 ENDP

PUBLIC ws_mask_xor_inplace_x64
PUBLIC ws_mask_xor_inplace_avx2_x64
; void ws_mask_xor_inplace_x64(uint8_t* buf, uint64_t len, uint32_t mask32)
; rcx=buf, rdx=len, r8d=mask32
ws_mask_xor_inplace_x64 PROC
    test rdx, rdx
    jz   inpl_done

    movd xmm0, r8d
    pshufd xmm0, xmm0, 0

inpl_xmm_loop:
    cmp rdx, 16
    jb  inpl_qword_loop
    movdqu xmm1, XMMWORD PTR [rcx]
    pxor xmm1, xmm0
    movdqu XMMWORD PTR [rcx], xmm1
    add rcx, 16
    sub rdx, 16
    jmp inpl_xmm_loop

inpl_qword_loop:
    cmp rdx, 8
    jb  inpl_tail
    mov r9d, r8d
    mov r10d, r8d
    shl r10, 32
    or  r9, r10
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

; void ws_mask_xor_inplace_avx2_x64(uint8_t* buf, uint64_t len, uint32_t mask32)
; rcx=buf, rdx=len, r8d=mask32
ws_mask_xor_inplace_avx2_x64 PROC
    test rdx, rdx
    jz   inpl_avx2_done

    vmovd xmm0, r8d
    vpbroadcastd ymm0, xmm0

inpl_avx2_loop:
    cmp rdx, 32
    jb  inpl_avx2_tail
    vmovdqu ymm1, YMMWORD PTR [rcx]
    vpxor ymm1, ymm1, ymm0
    vmovdqu YMMWORD PTR [rcx], ymm1
    add rcx, 32
    sub rdx, 32
    jmp inpl_avx2_loop

inpl_avx2_tail:
    vzeroupper
    test rdx, rdx
    jz   inpl_avx2_done
    jmp  ws_mask_xor_inplace_x64

inpl_avx2_done:
    vzeroupper
    ret
ws_mask_xor_inplace_avx2_x64 ENDP

_TEXT ENDS
END
