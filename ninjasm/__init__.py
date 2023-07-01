import click
import pathlib as pl
import subprocess as sp
from ninjasm.preprocessor import Parser
from ninjasm.generator import Generator
from ninjasm.asm import Asm
import sys
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
log = logging.getLogger(__file__)

class Arg:
    """
    Universal argument container
    """
    def __init__(self, **kwarg):
        self.update(kwarg)

    def update(self, d):
        for k, v in d.items():
            setattr(self, k, v)

## With click we handle some globals variables
args = Arg()

@click.group()
def cmd(**kwarg):
    global args
    args.update(kwarg)

@cmd.command()
@click.argument('ninja_file')
def treat_file(ninja_file):
    f = pl.Path(ninja_file).resolve()
    if not f.exists():
        raise RuntimeError(f"{f} didn't exists")
    comp(f)

@cmd.command()
@click.argument('ninja_path')
def treat_path(ninja_file):
    log.info(f"Ninjasm ")
    # FIXME: futur algo for build
    # lookup for *.asm in directory
    here = pl.Path('.').resolve()
    for f in here.glob('*.nja'):
        log.info(f"FOUND {f}")
        # FIXME: read a file
        comp(f)

def main():
    cmd()

def comp(f):
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
