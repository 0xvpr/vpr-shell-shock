global          entry
extern          _payload

section         .text
entry:
    push    ebp
    ;sub     rsp, 0x20

    call    _payload            ; Call to write_hello
    xor     eax, eax

    ;add     rsp, 0x20
    pop     ebp                 ; Restore rdi
    ret                         ; Return back to entry
