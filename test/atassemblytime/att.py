__out__ = ''
from ninjasm.asm import *
__out__ += f'\n'
def get_asm():
    __out__ = ''
    a = """;test\n""" + f''';don't bug here''' + f"""
    mov rax, 1
    mov rdi, 1
    mov rsi, msg
    mov rdx, len
    syscall
    """#endstr
    b = f"""
    mov rax, 1
    mov rdi, 1
    mov rsi, msg
    mov rdx, len
    syscall
    msg db "Hello World", 0xa
   ; len equ $ - msg
    end: resw 15
    other resb 100
    """#endstr
    ass = Asm(b)
    ass.assemble()
    print(f"Assembly {ass}")
    return ass

#
__out__ += f'\n'
def calc_ctf():
    __out__ = ''
    code = f"""
    mov rax, 42
    mov rdx, 2600
    add rax, rdx
    """#endstr
    ass = Asm(code)
    ass.assemble()
    ass.eval()
    print(f"EVAL RAX {ass.r_rax}")

# end_def
calc_ctf()
__out__ += f'\n'
__out__ += f'section .text\n'
__out__ += f'\n'
__out__ += f'    global _start\n'
__out__ += f'_start:\n'
__out__ += f'\n'
__out__ += f'    {get_asm().to_asm()}\n'
__out__ += f'\n'
__out__ += f'    mov rax, 60\n'
__out__ += f'    xor rdi, rdi\n'
__out__ += f'    syscall\n'
__out__ += f'\n'
__out__ += f'section .data\n'
__out__ += f'\n'
__out__ += f'    msg db "Hello World", 0xa\n'
__out__ += f'    len equ $ - msg\n'
with open('/home/iopi/Documents/Ninjasm/test/atassemblytime/att.nja', 'w') as f:
    f.write(__out__)
