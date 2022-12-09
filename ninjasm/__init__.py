import argparse
import pathlib as pl
import subprocess as sp
from ninjasm.preprocessor import Parser
from ninjasm.generator import Generator
from ninjasm.asm import Asm
import sys
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
log = logging.getLogger(__file__)

def main():
    log.info(f"Ninjasm ")
    # FIXME: futur algo for build
    # lookup for *.asm in directory
    here = pl.Path('.').resolve()
    for f in here.glob('*.nja'):
        log.info(f"FOUND {f}")
        # FIXME: read a file
        content = open(f).read()
        p = Parser()
        stmts = p.parse(content)
        g = Generator(stmts)
        s1 = f.with_suffix('.py')
        s2 = f.with_suffix('.asm')
        s3 = f.with_suffix('.o')
        if g.generate(s1, s2):
            # CALL Python to generate ASM
            sp.run(['python', s1])
            # CALL NASM to generate .O
            sp.run(['nasm', '-felf64', s2, '-O0', '-o', s3])
            #Content = open(s2).read()
            #A = Asm(content)
            #A.assemble()
