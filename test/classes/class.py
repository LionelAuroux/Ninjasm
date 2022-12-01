__out__ = ''
class Syscall:
    def __init__(self, sysnum, arity):
        __out__ = ''
        self.sysnum = sysnum
        self.arity = arity

    #enddef
    def __call__(self, *args):
        __out__ = ''
        if len(args) > self.arity:
            raise RuntimeError("Can't handle syscall with more than 5 parameters")
        #endif
        __out__ += f'                mov rax, {self.sysnum}\n'
        for idx, arg in enumerate(args):
            match idx:
                case 0:
                    __out__ += f'                        mov rdi, {arg}\n'
                case 1:
                    __out__ += f'                        mov rsi, {arg}\n'
                case 2:
                    __out__ += f'                        mov rdx, {arg}\n'
                case 3:
                    __out__ += f'                        mov r10, {arg}\n'
                case 4:
                    __out__ += f'                        mov r8, {arg}\n'
                case 5:
                    __out__ += f'                        mov r9, {arg}\n'
        #endfor
        __out__ += f'                syscall\n'
        return __out__
    # endcall
# some basic syscall
sysexit = Syscall(60, 1)
sysread = Syscall(0, 3)
syswrite = Syscall(1, 3)
sysopen = Syscall(2, 3)
sysclose = Syscall(3, 1)
__out__ += f'\n'
__out__ += f'section .text\n'
__out__ += f'\n'
__out__ += f'    global _start\n'
__out__ += f'    _start:\n'
__out__ += f'        {syswrite(1, "msg", "len_msg")}\n'
__out__ += f'        {sysexit(0)}\n'
__out__ += f'        ret\n'
__out__ += f'\n'
__out__ += f'section .data\n'
__out__ += f'    msg db "Hello World", 0xa\n'
__out__ += f'    len_msg equ $-msg\n'
with open('/home/iopi/Documents/Ninjasm/test/classes/class.nja', 'w') as f:
    f.write(__out__)
