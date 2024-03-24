global          entry

section         .text
payload:
    incbin      "cpp_out32.bin"
entry:
    push        edi
    call        payload
    xor         eax, eax
    pop         edi
    ret
