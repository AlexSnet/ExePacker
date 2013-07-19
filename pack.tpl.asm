use32
    ;push 0
    ;call dword [{{ imports["ExitProcess"] }}]
    mov eax, {{ go }}
    jmp eax