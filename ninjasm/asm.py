import re
from keystone import *
from capstone import *
from unicorn import *
from unicorn.x86_const import *

class XRef:
    def __init__(self, symbol, idx=0):
        from ctypes import c_ulong
        self.symbol = symbol
        self.code = None
        self.idx = idx # offset in memory
        self.szinsn = 0 # size of insn
        self.idxref = 0 # idx of the ref to change in insn
        self.value = 0

    def __repr__(self):
        return f"\n{self.symbol} at {self.idx} size {self.szinsn} idxref {self.idxref}: {self.code}"


class DirectiveParser:
    def __init__(self):
        directive_lang = rb"""(?mix)
        (?# Setup a Verbose, Unicode Regex
        )
        (?P<define>\s*
            (?:(?P<def_name>\w+)\s+)?
            (?P<def_type>d(?:b|w|dq|d|q|t|o))
            # NEXT list of constant
        )
        | (?P<reserve>\s*
            (?:(?P<res_name>\w+)\s+)?
            (?P<res_type>res(?:b|w|dq|d|q|t|o))\s+
            # size
            (?P<res_size>\d+)
            (?:;[^\n]+)? # extra comment
        )
        | (?P<label>\s*
            (?P<label_name>\w+)\s*:
            (?P<label_insn>[^\n]+)?
            (?:;[^\n]+)? # extra comment
        )
        | (?:\s*;[^\n]+) # one line comment
        """
        self.directive_parser = re.compile(directive_lang)
        constant_lang = rb"""(?mix)
        \s*
        (?:
          (?: # float
            (?: (?: \d+ \. \d*) | (?: \. \d+) )
            (?: [eE] [+-]? \d+ )?
            (?: [lL] )?
            (?: [fF] )?
            (?: [iIjJ] )?
         )
        | (?:
                (?:[1-9]+\d*) # decimal
                | (?: 0[bB][01]+) # binary literal
                | (?: 0[0-7]+(\. [0-7]+ ([pP] [+-]? \d+ )?)? ) # octal literal
                | (?: 0[xX][0-9a-fA-F]+[uU]?[lL]{,2}) # hexa literal
            )
            (?: # int_suffix
                [uU][lL]{,2}
                | [lL]{1,2}[uU]?
            )?
        | (?: ' (?: [^'\\] | \\. )* ' )
        | (?: " (?: [^"\\] | \\. )* " )
        )\s*
        (?:;[^\n]+)? # extra comment
        """
        self.const_parser = re.compile(constant_lang)

    def parse(self, content):
        # we will save statements in a list
        self.stmts = []
        # store last position
        pos = 0
        # read until end of content
        while pos < len(content):
            # try to parse something
            m = self.directive_parser.match(content, pos)
            # did we read something ?
            if m is None:
                # end to parse at pos
                return 0
            # store the result
            stmt = m.groupdict()
            adv = len(m.group(0))
            # special case for defines, read list of constant
            if 'define' in stmt:
                stmt['values'] = []
                print(f"DEFINE!!! {adv}")
                # advance
                pos += adv
                while pos < len(content):
                    m = self.const_parser.match(content, pos)
                    print(f"READ1 {content[pos:]}")
                    if m is None:
                        if content[pos] != b'\n': # handle end of string
                            p = re.compile(rb",\s*")
                            coma = p.match(content, pos)
                            if coma is not None:
                                adv = len(coma.group(0))
                                pos += adv
                                print(f"READ2 {content[pos:]}")
                        else:
                            print(f"READ3 {content[pos:]}")
                            break
                    else:
                        stmt['values'].append(m.group(0))
                        adv = len(m.group(0))
                        pos += adv
                print(f"READ4 {content[pos:]} / {stmt}")
            self.stmts.append(stmt)
            # advance
            pos += adv
        print(f"RETURN POS {pos}")
        return pos

    def get_stmts(self):
        return self.stmts

class Asm:
    def __init__(self, content):
        self.content = content
        self.encoding = None
        self.xref = {}
        self.last_xref = None
        self.dir_parse = DirectiveParser()
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)

    def sym_resolver(self, symbol, value):
        from ctypes import byref
        print(f"Must RESOLVE {symbol} {value}")
        if symbol not in self.xref:
            xr = XRef(symbol, len(self.encoding))
            self.last_xref = self.xref[symbol] = xr
            #value.value = 0#byref(xr.value)
            return False
        else:
            return True

    def get_insn(self, insn):
        # Filter directive ASM
        code, cnt = self.ks.asm(insn)
        if self.last_xref:
            self.last_xref.code = code
            self.last_xref.szinsn = len(code)
            pos = 0
            for pos, c in enumerate(reversed(code)):
                if c == 0xff:
                    break
            self.last_xref.idxref = len(code) - pos - 1
        return code, cnt

    def assemble(self):
        self.ks.sym_resolver = self.sym_resolver
        self.encoding, self.count = [], 0
        for insn in self.content.encode('utf-8').split(b'\n'):
            self.last_xref = None
            if insn.strip() == b"":
                continue
            print(f"ASS {insn}")
            code = None
            cnt = 0
            try:
                # Check Directive
                pos = self.dir_parse.parse(insn)
                if pos != 0:
                    print(f"Found directive")
                    stmts = self.dir_parse.get_stmts()
                    print()
                    print(f"Skipp...")
                    continue
                elif pos == 0:
                    print(f"No directive")
                code, cnt = self.get_insn(insn)
            except KsError as e:
                print(f"Error: {e}")
                if e.errno == KS_ERR_ASM_SYMBOL_MISSING:
                    print(f"HANDLE THIS ERROR for insn : {insn}")
                    new_insn = insn.replace(self.last_xref.symbol, b"0xff")
                    code, cnt = self.get_insn(new_insn)
            print(f"into {code}/{cnt}")
            self.encoding += code
            self.count += cnt
        bcode = ""
        for i in self.encoding:
            if i is not None:
                bcode += "%02x " % i
        print(f"<{self.content}> = [{bcode}]")
        print(f"ENCODE {self.count} instructions")
        print(f"XREF {self.xref}")

    def __str__(self):
        hexastr = ", ".join([("0x%02X" % it) for it in self.encoding if it is not None])
        return f"db {hexastr}"

    def to_bytes(self):
        return b"".join([it.to_bytes(1, 'big') for it in self.encoding])

    def to_asm(self):
        code = "\n".join([ f"{insn.mnemonic} {insn.op_str}" for insn in self.cs.disasm(self.to_bytes(), 0) ])
        return code

    def eval(self):
        BASE = 0x1000000
        self.uc.mem_map(BASE, 2 * 1024 * 1024)
        self.uc.reg_write(UC_X86_REG_RSP, BASE + 0x200000)
        code = self.to_bytes()
        self.uc.mem_write(BASE, code)
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        self.uc.reg_write(UC_X86_REG_RDX, 0)
        self.uc.emu_start(BASE, BASE + len(code))
        self.r_rax = self.uc.reg_read(UC_X86_REG_RAX)
