section .text
    global _start
    _start:
        ret

section .data
;>> for name in ['abc', 'def', 'ghi', 'klm']:
;>>     for idx in range(5):
            {name}{idx} db {', '.join(['10', '20', '30', '40', '50', '60', '70'])}
            len_{name}{idx} equ $-{name}{idx}
;>>     #endfor2
;>> #endfor1

;>> def f(a):
;>>     print(f'CALL F {a}')
        {a} db 2600
;>> #enddef

{f('tutu')} ; call a function
