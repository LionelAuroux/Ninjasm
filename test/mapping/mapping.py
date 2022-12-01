__out__ = ''
__out__ += f'section .text\n'
__out__ += f'    global _start\n'
__out__ += f'    _start:\n'
__out__ += f'        ret\n'
__out__ += f'\n'
__out__ += f'section .data\n'
for name in ['abc', 'def', 'ghi', 'klm']:
    for idx in range(5):
        __out__ += f'            {name}{idx} db {", ".join(["10", "20", "30", "40", "50", "60", "70"])}\n'
        __out__ += f'            len_{name}{idx} equ $-{name}{idx}\n'
    #endfor2
#endfor1
__out__ += f'\n'
def f(a):
    __out__ = ''
    print(f'CALL F {a}')
    __out__ += f'        {a} db 2600\n'
    return __out__
#enddef
__out__ += f'\n'
__out__ += f'{f("tutu")} ; call a function\n'
with open('/home/iopi/Documents/Ninjasm/test/mapping/mapping.nja', 'w') as f:
    f.write(__out__)
