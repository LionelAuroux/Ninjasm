__out__ = ''
import sys
print('This Part is in python')
print(f"So we have full access to python loaded in {sys.path}")
# Comment in generated file
__out__ += f'\n'
__out__ += f'section .text\n'
__out__ += f'\n'
__out__ += f'    global _start\n'
__out__ += f'    _start:\n'
__out__ += f'\n'
__out__ += f'        mov rax, 1      ; system call for write\n'
__out__ += f'        mov rdi, 1      ; file descriptor for STDOUT\n'
__out__ += f'        mov rsi, msg    ; address of string\n'
__out__ += f'        mov rdx, len    ; len\n'
__out__ += f'        syscall\n'
__out__ += f'        \n'
__out__ += f'        mov rax, 60\n'
__out__ += f'        xor rdi, rdi\n'
__out__ += f'        syscall\n'
__out__ += f'\n'
__out__ += f'section .data\n'
__out__ += f'\n'
__out__ += f'    msg db "Hello, World", 0xa\n'
__out__ += f'    len equ $ - msg     ; len of msg\n'
__out__ += f'\n'
for it in range(10):
    __out__ += f'    data{it} db {10+it}\n'
#endfor
with open('/home/iopi/Documents/Ninjasm/test/helloworld/helloworld.nja', 'w') as f:
    f.write(__out__)
