OPTION CASEMAP:NONE

_TEXT SEGMENT

PUBLIC funasr_find_text_key_x64
; const char* funasr_find_text_key_x64(const char* buf, uint64_t len)
; rcx=buf, rdx=len
funasr_find_text_key_x64 PROC
    cmp rdx, 8
    jb  text_not_found

    ; candidates = len - 8 + 1
    sub rdx, 8
    inc rdx
text_loop:
    mov r8, QWORD PTR [rcx]
    mov r9, 223A227478657422h ; "\"text\":\""
    cmp r8, r9
    je  text_found
    inc rcx
    dec rdx
    jnz text_loop

text_not_found:
    xor rax, rax
    ret

text_found:
    lea rax, [rcx + 8]
    ret
funasr_find_text_key_x64 ENDP

PUBLIC funasr_find_is_final_key_x64
; const char* funasr_find_is_final_key_x64(const char* buf, uint64_t len)
; rcx=buf, rdx=len
funasr_find_is_final_key_x64 PROC
    cmp rdx, 10
    jb  final_not_found

    ; candidates = len - 10 + 1
    sub rdx, 10
    inc rdx
final_loop:
    mov r8, QWORD PTR [rcx]
    mov r9, 616E69665F736922h ; "\"is_fina"
    cmp r8, r9
    jne final_next
    movzx r9d, WORD PTR [rcx + 8]
    cmp r9w, 0226Ch            ; "l\""
    je  final_found

final_next:
    inc rcx
    dec rdx
    jnz final_loop

final_not_found:
    xor rax, rax
    ret

final_found:
    lea rax, [rcx + 10]
    ret
funasr_find_is_final_key_x64 ENDP

_TEXT ENDS
END
