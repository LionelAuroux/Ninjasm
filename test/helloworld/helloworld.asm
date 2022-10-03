;>> import sys
;>> print('This Part is in python')
;>> print(f"So we have full access to python loaded in {sys.path}")
;>> # Comment in generated file

section .text

    global _start
    _start:

        mov rax, 1      ; system call for write
        mov rdi, 1      ; file descriptor for STDOUT
        mov rsi, msg    ; address of string
        mov rdx, len    ; len
        syscall
        
        mov rax, 60
        xor rdi, rdi
        syscall

section .data

    msg db "Hello, World", 0xa
    len equ $ - msg     ; len of msg

;>> for it in range(10):
    data{it} db {10+it}
;>> #endfor
