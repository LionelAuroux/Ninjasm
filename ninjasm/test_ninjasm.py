from ninjasm import *
#from ninjasm.elf import *
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

def test_insn():
    """
    Encode une seule instruction
    """
    ass = Asm("")
    out = ass.get_insn(b"mov rax, 2600")
    log.info(f"OUT {out}")
    log.info(f"TYPE {type(out)}")

def test_flat():
    f = Flat()
    f.db('12')
    b = f.bytes
    log.info(f"DATA {b}")
    assert b == b'\x0c'
    f = Flat()
    f.db('1')
    b = f.bytes
    log.info(f"DATA {b}")
    assert b == b'\x01'
    f = Flat()
    f.db('1b')
    b = f.bytes
    log.info(f"DATA {b}")
    assert b == b'\x01'
    f = Flat()
    f.db('Ah')
    b = f.bytes
    log.info(f"DATA {b}")
    assert b == b'\x0A'
    f = Flat()
    f.db(12)
    b = f.bytes
    log.info(f"DATA {b}")
    assert b == b'\x0c'
    f = Flat()
    f.db('0xfa')
    b = f.bytes
    log.info(f"DATA {b}")
    assert b == b'\xfa'
    f = Flat()
    f.db('0o65')
    b = f.bytes
    log.info(f"DATA {b}")
    assert b == b'5'
    f = Flat()
    f.db('0b1111')
    b = f.bytes
    log.info(f"DATA {b}")
    assert b == b'\x0f'

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
        mov rax, 2600
    """
    ass = Asm(asm)
    ass.assemble()
    ass.resolve()
    log.info(f"XREF {ass.xref}")
    log.info(f"DEFS {ass.defs}")
    log.info(f"CODE {ass.to_asm()}")
    ass.eval()
    assert 'RAX' in ass.regs_values and ass.regs_values['RAX'] == 2600
    log.info(f"DEFS {ass.defs}")
    adr = ass.defs[b'buff'][b'offs'] + 0x401000
    sz = ass.defs[b'buff'][b'len']
    log.info(f"ADR OF BUFF {adr}: {sz}")
    ar = ass.uc.mem_read(adr, sz)
    log.info(f"MEM {ar}")
    for it in range(sz):
        assert ar[it] == 0x90
