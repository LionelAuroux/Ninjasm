##########GENERATED! DO NOT EDIT##########
__out__ = ''
from ninjasm.asm import *
def get_asm():
    __out__ = ''
    a = """;test\n""" + f''';don't bug here''' + f"""
    mov rax, 1
    mov rdi, 1
    mov rsi, 0xcafebabe
    mov rdx, 0xdeadbeef
    syscall
    """#endstr
    b = f"""
    mov rax, 1
    mov rdi, 1
    mov rsi, msg ; xref
    mov rdx, msg.len ; property of symbol
    syscall
    msg db "Hello World", 0xa
    ;len equ $ - msg ;!!! len(__local__.msg)
    end: resw 15
    other resb 100
    """#endstr
    ass = Asm(b)
    ass.assemble()
    ass.resolve()
    print(f"Assembly {ass}")
    return ass

#
def calc_ctf():
    __out__ = ''
    code = f"""
    mov rax, 12
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
asm = get_asm()
__out__ += f'\n'
__out__ += f'section .text\n'
__out__ += f'\n'
__out__ += f'    global _start\n'
__out__ += f'_start:\n'
__out__ += f'\n'
__out__ += f'    {asm.to_asm()}\n'
__out__ += f'\n'
__out__ += f'    mov rax, 60\n'
__out__ += f'    xor rdi, rdi\n'
__out__ += f'    syscall\n'
__out__ += f'\n'
__out__ += f'\n'
__out__ += f'\n'
__out__ += f'\n'
__out__ += f'section .data\n'
__out__ += f'\n'
__out__ += f'    msg db "Hello World", 0xa\n'
__out__ += f'    {asm.to_dbstr()}\n'
__out__ += f'\n'
__out__ += f'\n'
__out__ += f'\n'
__out__ += f'\n'
##########END OF GENERATED##########
with open('/home/iopi/Documents/Ninjasm/test/atassemblytime/att.asm', 'w') as f:
    f.write(__out__)
