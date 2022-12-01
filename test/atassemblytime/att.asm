;>> from ninjasm.asm import *

;>> def get_asm():
;>>     a = """;test\n""" + f''';don't bug here''' + f"""
    mov rax, 1
    mov rdi, 1
    mov rsi, msg
    mov rdx, len
    syscall
;>>     """
;>>     b = f"""
    mov rax, 1
    mov rdi, 1
    mov rsi, msg
    mov rdx, len
    syscall
    msg db "Hello World", 0xa
   ; len equ $ - msg
    end: resw 15
    other resb 100
;>>     """
;>>     ass = Asm(b)
;>>     ass.assemble()
;>>     print(f"Assembly {ass}")
;>>     return ass
;>> #

;>> def calc_ctf():
;>>     code = f"""
    mov rax, 42
    mov rdx, 2600
    add rax, rdx
;>>     """
;>>     ass = Asm(code)
;>>     ass.assemble()
;>>     ass.eval()
;>>     print(f"EVAL RAX {ass.r_rax}")
;>> # end_def
;>> calc_ctf()

section .text

    global _start
_start:

    {get_asm().to_asm()}

    mov rax, 60
    xor rdi, rdi
    syscall

section .data

    msg db "Hello World", 0xa
    len equ $ - msg
