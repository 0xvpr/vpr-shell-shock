global          entry

section         .text
payload:
    incbin      "out64.bin"
entry:
    push        rdi             ; Backup rdi
    mov         rdi, rsp        ; Save the stack pointer to rdi
    sub         rsp, 0x20

    call        payload
    xor         eax, eax

    add         rsp, 0x20
    pop         rdi             ; Restore rdi
    ret                         ; Return back to entry
