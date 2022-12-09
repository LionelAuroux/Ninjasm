# Ninjasm

Python + ASM for Ninja

Ninjasm is a Python module and a template preprocessor for Assembly language.

## Platform

The actual version support:

- Linux operating system

## Assembly

The actual version support:

- nasm syntax

## Architecture

The actual version support:

- x86_64

## Installation

```bash
    $ git clone https://github.com/LionelAuroux/Ninjasm.git
    $ cd Ninjasm
    $ python3 -m build
    $ pip install .
```

## Usage

Ninjasm is an assembly language (nasm dialect) using python as macro processor.

You could consult sample code [here](test/).

### Basic macro processing.

However, a typical Ninjasm code look like this...

```asm

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
```

For a classical example, write the previous code into the `class.nja` file.

```bash
    $ ls
    class.nja
    $ ninjasm
    $ ls
    class.asm class.nja class.o class.py
```

Ninjasm will :
+ parse your __class.nja__ code and produce a __class.py__ file...
+ call *python3* on your __class.py__ file and produce a __class.asm__ file...
+ call *nasm* on your __class.asm__ file and procude a __class.o__ file...

You are free to link this __.o__ with other project, or to produce a binary with it (if it contain an "\_start" symbol).

```bash
    $ ls class.o
    class.o
    $ ld class.o -o test
    $ ./test
    Hello world
    $
```

### Payload expension.

You could also produce payloads.

```asm
    ;>> import sys
    ;>> from ninjasm.asm import *
    ;>> print('This Part is in python')
    ;>> print(f"So we have full access to python loaded in {sys.path}")
    ;>> # Comment in generated file
    ;>> a = f"""
            mov rax, 1          ; system call for write
            mov rdi, 1          ; file descriptor for STDOUT
            mov rsi, msg        ; address of string in the section
            mov rdx, msg.len    ; len property of the 'db'
            syscall

            mov rax, 60
            xor rdi, rdi
            syscall

            msg db "Hello, World", 0xa

    ;>> """
    ;>> ass = Asm(a)
    ;>> ass.assemble()
    ;>> ass.resolve()

    section .text

        global _start
        _start:
            
            {ass.to_asm()}
```

## Features

- Full power of Python for processing your assembly code.
- Thanks to [Keystone](https://www.keystone-engine.org) for compile time binary code production.
- Thanks to [Unicorn](https://www.unicorn-engine.org/) for compile time binary evaluation.
- Thanks to [Capstone](https://www.capstone-engine.org) for compile time binary disassembling.


### TODO
- __ELF Relocatable__ Support: No more need of *nasm* to producing ELF file.
