from ninjasm import *
from ninjasm.elf import *
import pathlib as pl
from elftools.elf.elffile import ELFFile
import re
import logging

log = logging.getLogger(__name__)
here = pl.Path(__file__).resolve().parent

def test_directive():
    log.info(f"PLOP")

def test_elf():
    log.info(f"ELF")
    test_example = None
    example_file = (here / '..' / 'test' / 'helloworld' / 'helloworld.o').resolve()
    if example_file.exists():
        with open(example_file, 'rb') as f:
            test_example = f.read()
        elf_data = elf_file.parse(test_example)
        log.info(f"DUMP ELF: {elf_data}")
    else:
        log.info(f"NEED TO ASSEMBLE CREASTE {example_file}")

def test_elftools():
    example_file = (here / '..' / 'test' / 'helloworld' / 'helloworld.o').resolve()
    if example_file.exists():
        elffile = ELFFile(open(example_file, 'rb'))
        for section in elffile.iter_sections():
            log.info(f"SECTION {section} {vars(section)}")
            if section['sh_type'] == 'SHT_SYMTAB':
                log.info(f"SYMBOLS!!")
                for sym in section.iter_symbols():
                    log.info(f"SYM {sym}: <{sym.entry.keys()}> - <{sym.name}>")

def test_asmback():
    asm = """
    mov rsi, msg
    mov rdx, len
    """
    ass = Asm(asm)
    ass.assemble()
    # check XRef
    assert b'msg' in ass.xref
    assert b'len' in ass.xref
    # add definition for one
    ass.add_def(b'b', b'len', [0], 0)
    assert b'len' in ass.defs
    ass.resolve()
    txt = ass.to_asm()
    assert bool(re.search("mov rsi, msg", txt))

def test_eval():
    asm = """
    mov rax, 12
    mov rdx, 2600
    add rax, rdx
    """
    ass = Asm(asm)
    ass.assemble()
    ass.resolve()
    log.info(f"CODE {ass.to_dbstr()}")
    ass.eval()
    #log.info(f"REGS {ass.regs_names}")
    assert 'RAX' in ass.regs_values and ass.regs_values['RAX'] == 2612

def test_evalcpy():
    asm = """
    mov rdi, buff
    mov rcx, buff.len
    mov al, 0x90
    loop:
        stosb
        dec rcx
        jnz loop
        jmp end
    buff db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
         db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
         db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
         db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    end:
    """
    ass = Asm(asm)
    ass.assemble()
    ass.resolve()
    log.info(f"CODE {ass.to_dbstr()}")
    ass.eval()
    log.info(f"CODE {ass.to_asm()}")