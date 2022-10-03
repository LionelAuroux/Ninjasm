import argparse
import pathlib as pl
import subprocess as sp
from ninjasm.parser import Parser
from ninjasm.generator import Generator
from ninjasm.asm import Asm

def main():
    print(f"Ninjasm ")
    # FIXME: futur algo for build
    # lookup for *.asm in directory
    here = pl.Path('.').resolve()
    for f in here.glob('*.asm'):
        print(f"FOUND {f}")
        # FIXME: read a file
        content = open(f).read()
        p = Parser()
        stmts = p.parse(content)
        print(f"RESULT {stmts}")
        g = Generator(stmts)
        s1 = f.with_suffix('.py')
        s2 = f.with_suffix('.nja')
        s3 = f.with_suffix('.o')
        g.generate(s1, s2)
        # CALL Python to generate ASM
        sp.run(['python3.10', s1])
        # CALL NASM to generate .O
        sp.run(['nasm', '-felf64', s2, '-o', s3])
        content = open(s2).read()
        a = Asm(content)
        a.assemble()
