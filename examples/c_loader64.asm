global          entry

section         .text
payload:
    incbin      "c_out64.bin"
entry:
    push        rdi
    call        payload
    xor         eax, eax
    pop         rdi
    ret
