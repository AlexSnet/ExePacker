use32

;======================== COPY CODE to original
mov ebx, {{ copy_from+copy_len-1 }}
mov edx, {{ copy_to+copy_len-1 }}
mov ecx, {{ copy_len-1 }}

copy_loop:

mov al, [ebx]
mov [edx], al

cmp ecx, 0
jz end_copy_loop

dec ebx
dec edx
dec ecx
jmp copy_loop

end_copy_loop:

;======================== XOR 1 section
mov ebx, {{ copy_to+xor_len-1 }}
mov ecx, {{ xor_len-1 }}

xor_loop:
mov al, byte [ebx]
xor al, {{ key_encode }}
mov byte [ebx], al

cmp ecx, 0
jz stop_loop

dec ebx
dec ecx
jmp xor_loop

stop_loop:

;========================== GO OEP

push {{ original_eop }}
ret
