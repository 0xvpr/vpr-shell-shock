global          entry

section         .text
payload:
    incbin      "c_out32.bin"
entry:
    push        edi
    call        payload
    xor         eax, eax
    pop         edi
    ret
