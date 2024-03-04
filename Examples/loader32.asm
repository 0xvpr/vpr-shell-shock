global          entry

section         .text
payload:
    incbin      "out32.bin"
entry:
    push        ebp
;   sub         rsp, 0x20

    call        payload         ; Call to write_hello
    xor         eax, eax

;   add         rsp, 0x20
    pop         ebp             ; Restore ebp
    ret                         ; Return back to entry
