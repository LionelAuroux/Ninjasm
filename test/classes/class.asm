;>> class Syscall:
;>>     def __init__(self, sysnum, arity):
;>>         self.sysnum = sysnum
;>>         self.arity = arity
;>>     #enddef
;>>     def __call__(self, *args):
;>>         if len(args) > self.arity:
;>>             raise RuntimeError("Can't handle syscall with more than 5 parameters")
;>>         #endif
                mov rax, {self.sysnum}
;>>         for idx, arg in enumerate(args):
;>>             match idx:
;>>                 case 0:
                        mov rdi, {arg}
;>>                 case 1:
                        mov rsi, {arg}
;>>                 case 2:
                        mov rdx, {arg}
;>>                 case 3:
                        mov r10, {arg}
;>>                 case 4:
                        mov r8, {arg}
;>>                 case 5:
                        mov r9, {arg}
;>>         #endfor
                syscall
;>>     # endcall
;>> # some basic syscall
;>> sysexit = Syscall(60, 1)
;>> sysread = Syscall(0, 3)
;>> syswrite = Syscall(1, 3)
;>> sysopen = Syscall(2, 3)
;>> sysclose = Syscall(3, 1)

section .text

    global _start
    _start:
        {syswrite(1, 'msg', 'len_msg')}
        {sysexit(0)}
        ret

section .data
    msg db "Hello World", 0xa
    len_msg equ $-msg
