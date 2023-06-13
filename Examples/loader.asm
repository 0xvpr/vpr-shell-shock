global          entry
extern          payload

section         .text
entry:
    push    rdi                 ; Backup rdi
    mov     rdi, rsp            ; Save the stack pointer to rdi
    sub     rsp, 0x20

    call    payload             ; Call to write_hello
    xor     eax, eax

    add     rsp, 0x20
    pop     rdi                 ; Restore rdi
    ret                         ; Return back to entry
