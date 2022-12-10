"""
Assembly core for Ninjasm

    - Ninjasm directive follow yasm/nasm section/global/db
    - Could Eval Assembly instruction at assembly time for metaprogramming
"""

import re
import struct
from keystone import *
from capstone import *
from unicorn import *
from unicorn import x86_const as ucc
import logging

log = logging.getLogger(__file__)

class XRef:
    """
    For X reference of label/name in instructions
    """
    def __init__(self, symbol, idx=0, section='.text'):
        from ctypes import c_ulong
        self.symbol = symbol
        self.fullsymbol = symbol
        self.code = None
        self.idx = idx # offset in memory
        self.szinsn = 0 # size of insn
        self.idxref = 0 # idx of the ref to change in insn
        self.value = None
        self.section = section
        self.resolved = False
        self.is_relative = False

    def __repr__(self):
        return f"\n{self.fullsymbol} at {self.idx} size {self.szinsn} idxref {self.idxref}: {self.code}"

    def get_resolved(self, assembly, base_address):
        """
        Resolved the XRef with the specified base_address
        """
        # handle property or local label
        val = None
        self.resovled = True
        if hasattr(self, 'attr'):
            if self.attr == b'len':
                val = assembly.defs[self.symbol][b'len']
        else:
            if not self.is_relative:
                val = assembly.defs[self.symbol][b'offs'] + base_address # FIXME: raw start address
            else:
                val = assembly.defs[self.symbol][b'offs'] - self.idx - self.szinsn
        nbytes = self.szinsn - self.idxref
        log.info(f"GETSUBL for {self.fullsymbol} : {val} by {nbytes} bytes")
        fmt = None
        match nbytes:
            case 8:
                fmt = 'l'
            case 4:
                fmt = 'i'
            case 2:
                fmt = 'h'
            case 1:
                fmt = 'b'
        self.value = val
        return list(struct.pack(fmt, self.value))

class DirectiveParser:
    """
    Handle specific Ninjasm directive
    """
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
        | (?P<section>\s*
            section\s*
            (?P<section_name>\w+)\s*
            (?:;[^\n]+)? # extra comment
        )
        | (?P<global>\s*
            global\s*
            (?P<global_name>\w+)\s*
            (?:;[^\n]+)? # extra comment
        )
        | (?P<extern>\s*
            extern\s*
            (?P<extern_name>\w+)\s*
            (?:;[^\n]+)? # extra comment
        )
        | (?P<static>\s*
            static\s*
            (?P<static_name>\w+)\s*
            (?:;[^\n]+)? # extra comment
        )
        | (?P<origin>\s*
            org\s*
            (?P<origin_address>\d+)\s*
            (?:;[^\n]+)? # extra comment
        )
        | (?P<default>\s*
            default\s*
            (?P<default_addressing>\w+)\s*
            (?:;[^\n]+)? # extra comment
        )
        | (?:\s*;[^\n]+) # one line comment
        """
        self.directive_parser = re.compile(directive_lang)
        constant_lang = rb"""(?mix)
        \s*
        (?:
            (?: # float
                (?P<float_val>
                    (?: (?: \d+ \. \d*) | (?: \. \d+) )
                    (?: [eE] [+-]? \d+ )?
                )
            #(?: [lL] )?
            #(?: [fF] )?
            #(?: [iIjJ] )?
            )
        |   (?:
                (?P<int_val>
                    (?:[1-9]+\d*) # decimal
                    | (?: 0[bB][01]+) # binary literal
                    | (?: 0[0-7]+(\. [0-7]+ ([pP] [+-]? \d+ )?)? ) # octal literal
                    | (?: 0[xX][0-9a-fA-F]+ # [uU]?[lL]{,2}
                        ) # hexa literal
                )
            )
            #(?: # int_suffix
            #    [uU][lL]{,2}
            #    | [lL]{1,2}[uU]?
            #)?
        | (?: ' (?P<qstr_val> (?: [^'\\] | \\. )* ) ' )
        | (?: " (?P<dqstr_val> (?: [^"\\] | \\. )* ) " )
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
            # TODO : read dup(X) and dup(?)
            if 'define' in stmt and stmt['define'] is not None:
                # FIXME: when def_name is null, attach to the previous def_name!!!
                stmt['values'] = []
                log.info(f"DEFINE!!! {adv}")
                # advance
                pos += adv
                while pos < len(content):
                    m = self.const_parser.match(content, pos)
                    log.info(f"READ1 {content[pos:]}")
                    if m is None:
                        if content[pos] != b'\n': # handle end of string
                            p = re.compile(rb",[\s]*")
                            coma = p.match(content, pos)
                            if coma is not None:
                                adv = len(coma.group(0))
                                pos += adv
                                log.info(f"READ2 {content[pos:]}")
                        else:
                            log.info(f"READ3 {content[pos:]}")
                            break
                    else:
                        g = m.groupdict()
                        v = None
                        for t in ['float_val', 'int_val', 'qstr_val', 'dqstr_val']:
                            if g[t] is not None:
                                v = (t, g[t])
                                break
                        stmt['values'].append(v)
                        adv = len(m.group(0))
                        pos += adv
                log.info(f"READ4 {content[pos:]} / {stmt}")
            self.stmts.append(stmt)
            # advance
            pos += adv
        log.info(f"RETURN POS {pos}")
        return pos

    def get_stmts(self):
        return self.stmts

def handle_directive(assembly, directive):
    import sys
    log.info(f"HANDLE {directive}")
    if directive['define'] is not None:
        # FIXME: add dup(XX) in the directive
        df = directive['def_name']
        dt = directive['def_type']
        buf = []
        log.info(f"DEF {df}")
        # FIXME: for now handle only bytes
        for t, v in directive['values']:
            log.info(f"Encode {t}: {v}")
            match t:
                case 'int_val':
                    # handle prefix, else simple int
                    if v[0] == ord(b'0'):
                        if v[1] in set(b'xX'):
                            # hexa
                            v = int(v[2:], 16)
                        elif v[1] in set(b'bB'):
                            # binary
                            v = int(v[2:], 2)
                        else:
                            # octal
                            v = int(v[2:], 8)
                    buf += [v]
                case 'float_val': # FIXME: quid of double
                    buf += [ord(b) for b in struct.pack('f', float(v))]
                case ('qstr_val' | 'dqstr_val'):
                    # bytes as iterable is directly converted in int
                    buf += list(v)
                case other:
                    raise RuntimeError(f"Unhandle type {other}")
        begin = assembly.sections[assembly.current_section]['size']
        if df is None:
            # lookup for last define
            assembly.upd_def(dt, buf)
        else:
            assembly.add_def(dt, df, buf, begin)
        log.info(f"END DEFS {assembly.defs[assembly.last_def]}")
        assembly.sections[assembly.current_section]['opcodes'] += buf
        assembly.sections[assembly.current_section]['size'] += len(buf)
        assembly.sections[assembly.current_section]['from_other'] |= set(range(begin, begin + len(buf)))
        log.info(f"BUF {buf}")
    elif directive['reserve'] is not None:
        log.info(f"RES")
        rf = directive['res_name']
        rt = directive['res_type']
        rs = directive['res_size']
        # TODO
    elif directive['label'] is not None:
        log.info(f"LABL")
        if directive['label_insn'] is not None:
            raise RuntimeError(f"Don't handle labeled insn for now! put it in another line")
        ln = directive['label_name']
        offs = assembly.sections[assembly.current_section]['size']
        assembly.add_label(ln, offs)
    elif directive['section'] is not None:
        log.info(f"SECT")
    elif directive['global'] is not None:
        log.info(f"GLB")
    elif directive['extern'] is not None:
        log.info(f"EXT")
    elif directive['static'] is not None:
        log.info(f"STAT")
    elif directive['origin'] is not None:
        log.info(f"ORG")
    elif directive['default'] is not None:
        log.info(f"DFLT")

def handle_decimal_value(insn):
    import sys
    import re
    log.info(f"CHECK {insn}")
    # FIXME: avoir hexa value without 0x
    m = re.search(rb"(?i)(?P<int>(0[xb]?)?[1-9]\d*)", insn)
    if m is not None:
        num = m.groupdict()['int']
        log.info(f"found something {num}")
        if num[0] == ord('0'):
            log.info(f"PREFX {num[:2]}")
            if num[1] in [ord('x'), ord('X')]:
                hexa = num[2:]
                log.info(f"HEXA {hexa}")
                insn = insn.replace(num, hexa)
                log.info(f"write1 {insn}")
            elif num[1] in [ord('b'), ord('B')]:
                bnum = bytes(hex(int(num[2:], 2)), 'utf-8')
                insn = insn.replace(num, bnum)
                log.info(f"write2 {insn}")
            return insn
        log.info(f"Need to convert! {num[0]}")
        hnum = bytes(hex(int(num)), 'utf-8')
        insn = insn.replace(num, hnum)
        log.info(f"Write3 {insn}")
    return insn

class Asm:
    """
    Build file
    """
    def __init__(self, content):
        self.content = content
        # for cross reference
        self.xref = {}
        self.last_xref = None
        self.last_def = None
        # for definitions
        self.defs = {}
        # parser for Ninjasm directive
        self.dir_parse = DirectiveParser()
        # 3 devil tools
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        self.ks.syntax = KS_OPT_SYNTAX_NASM
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        # for sections handling
        self.current_section = ".text"
        self.sections = {".text": {"opcodes": [], "size": 0, "from_asm": set(), "from_other": set()}}
        self.register_map()

    def add_label(self, lbl_name, offs):
        self.defs[lbl_name] = {b"offs": offs}

    def add_def(self, def_type, def_name, buf, offs):
        self.last_def = def_name
        self.defs[def_name] = {b"offs": offs, b"len": len(buf), b"bytes": buf, b"type": def_type}

    def upd_def(self, def_type, buf):
        old_dt = self.defs[self.last_def][b'type']
        if def_type != old_dt:
            raise RuntimeError(f"Incompatible type of this buffer({def_type}) and the previous({old_dt})")
        self.defs[self.last_def][b"len"] += len(buf)
        self.defs[self.last_def][b"bytes"] += buf

    def sym_resolver(self, symbol, value):
        from ctypes import byref
        log.info(f"Must RESOLVE {symbol} {value}")
        # for label we are called twice, skip
        if symbol in self.xref:
            log.info(f"Already defined, skip")
            return False
        # check for property
        components = None
        if b'.' in symbol and symbol[0] != '.': # dot as prefix for local label like Nasm
            components = symbol.split(b'.')
            if len(components) > 2:
                raise RuntimeError(f"Can't handle more than one dot for property")
            symbol = components[0]
        xr = XRef(symbol, len(self.sections[self.current_section]['opcodes']), self.current_section)
        # add optional property
        if components:
            xr.attr = components[1]
            xr.fullsymbol += b'.' + xr.attr
        if symbol not in self.xref:
            self.xref[symbol] = []
        self.last_xref = xr
        self.xref[symbol].append(xr)
        log.info(f"{symbol} -> {xr}")
        return False

    def get_insn(self, insn):
        # Filter directive ASM
        # FIXME: keystone force setRadix(16) in LLVM engine
        # parse and transform numerical constant into hexadecimal
        # clean insn
        insn = insn.lstrip()
        code, cnt = self.ks.asm(handle_decimal_value(insn))
        log.info(f"GETINSN {code} {cnt}")
        if self.last_xref:
            self.last_xref.code = code
            self.last_xref.szinsn = len(code)
            pos = 0
            for pos, c in enumerate(reversed(code)):
                if c != 0:
                    break
            if pos == 0 and code[-1] != 0x0:
                raise RuntimeError("Error didn't the 0x0! label ?")
            self.last_xref.idxref = len(code) - pos
        return code, len(code)

    def assemble(self):
        self.ks.sym_resolver = self.sym_resolver
        self.sections[self.current_section]['opcodes'], self.sections[self.current_section]['size'] = [], 0
        for insn in self.content.encode('utf-8').split(b'\n'):
            self.last_xref = None
            if insn.strip() == b"":
                continue
            log.info(f"ASS {insn}")
            code = None
            size = 0
            try:
                # Check Directive
                pos = self.dir_parse.parse(insn)
                if pos != 0:
                    log.info(f"Found directive")
                    stmts = self.dir_parse.get_stmts()
                    # process directive
                    for stmt in stmts:
                        handle_directive(self, stmt)
                    log.info(f"Skip...")
                    continue
                elif pos == 0:
                    log.info(f"No directive")
                code, size = self.get_insn(insn)
            except KsError as e:
                log.info(f"Error: {e}")
                if e.errno == KS_ERR_ASM_SYMBOL_MISSING:
                    insn = insn.lstrip()
                    log.info(f"HANDLE THIS ERROR for insn : {insn}")
                    # mark for x referencing
                    new_insn = None
                    # FIXME : For Jcc/Jmp and Call must do some dirty trick
                    magic_value = b"0x00"
                    log.info(f"INSN {insn[0]} or {insn}")
                    if insn[0] == ord(b'j'):
                        # FIXME: other case for relative addressing?
                        self.last_xref.is_relative = True
                        # because the number bytes of instruction is 2
                        magic_value = b"0x02"
                    elif insn == b"call":
                        # because the number bytes of instruction is 5
                        magic_value = b"0x05"
                    new_insn = insn.replace(self.last_xref.fullsymbol, magic_value)
                    code, size = self.get_insn(new_insn)
            log.info(f"into {code}/{size}")
            begin = self.sections[self.current_section]['size']
            self.sections[self.current_section]['opcodes'] += code
            self.sections[self.current_section]['size'] += size
            self.sections[self.current_section]['from_asm'] |= set(range(begin, begin + size))
        bcode = ""
        for section, data in self.sections.items():
            # iterate thru sections
            for i in data['opcodes']:
                log.info(f"{type(i)} / {i}")
                if i is not None:
                    bcode += "%02x " % i
            log.info(f"ENCODE {data['size']} instructions")
        log.info(f"ENDXREF {self.xref}")
        log.info(f"END ASSEMBLE <{self.content}> = [{bcode}]")

    def resolve(self, base_address=0x401000):
        log.info(f"RESOLVE DEFS")
        for dn in self.defs.keys():
            log.info(f"SET XREF for {dn}")
            for xr in self.xref[dn]:
                for idx, v in enumerate(xr.get_resolved(self, base_address)):
                    subidx = xr.idx + xr.idxref + idx
                    log.info(f"XREFVAL {subidx} = {v}")
                    self.sections[xr.section]['opcodes'][subidx] = v
        # FIXME: Need to detect unresolved XRef, by default, rest untouched and be reverse into ASM with to_asm to allow iterative generation

    def to_dbstr(self, section='.text', begin=0, end=None):
        if end is None:
            end = self.sections[section]['size']
        log.info(f"DBSTR {begin} {end} in {section}")
        hexastr = ", ".join([("0x%02X" % it) for it in self.sections[section]['opcodes'][begin:end] if it is not None])
        return f"db {hexastr}"

    def to_bytes(self, section='.text', begin=0, end=None):
        log.info(f"TOBYTES {begin} {end} : section {section}")
        log.info(f"SECTION {self.sections[section]}")
        if end is None:
            end = self.sections[section]['size']
        return b"".join([it.to_bytes(1, 'big') for it in self.sections[section]['opcodes'][begin:end]])

    def to_asm(self, section='.text'):
        code = []
        pos = 0
        szcode = self.sections[section]['size']
        fa = self.sections[section]['from_asm']
        fo = self.sections[section]['from_other']
        log.info(f"From ASM {fa}")
        log.info(f"From Other {fo}")
        # treat unresolved XRef to be untouched in ASM...
        unresolved_adr = {}
        for xrlist in self.xref.values():
            for xr in xrlist:
                if not xr.resolved:
                    if xr.idx not in unresolved_adr:
                        unresolved_adr[xr.idx] = xr
        while True:
            log.info(f"POS {pos} {szcode}")
            if pos >= szcode:
                break
            # treat only one instruction with this for loop
            for insn in self.cs.disasm(self.to_bytes(section, begin=pos), 0):
                if pos in self.sections[section]['from_asm']:
                    raw_opstr = insn.op_str
                    if pos in unresolved_adr:
                        log.info(f"unresolved at {insn.address} with {raw_opstr}")
                        magic_value = "0x00"
                        # FIXME: for unresolved Jcc/JMP and call, the magic value differ
                        if insn.mnemonic[0] == ord(b'j'):
                            magic_value = "0x02"
                        elif insn.mnemonic == b"call":
                            magic_value = "0x05"
                        raw_opstr = raw_opstr.replace(magic_value, unresolved_adr[pos].fullsymbol.decode('utf-8'))
                    txtcode = f"{insn.mnemonic} {raw_opstr}"
                    log.info(f"DISASM {pos} {txtcode} {insn.bytes}")
                    code.append(txtcode)
                    pos += insn.size
                    break
            if pos in self.sections[section]['from_other']:
                log.info(f"OTHER {pos}")
                end = None
                for idx in range(pos, szcode):
                    log.info(f"LOOKUP {idx}")
                    if idx not in self.sections[section]['from_other']:
                        end = idx
                        break
                else:
                    end = szcode
                log.info(f"OTHER POS {pos} {end}")
                code.append(self.to_dbstr(begin=pos, end=end+1))
                pos += end
        return "\n".join(code)

    def register_map(self):
        # FIXME: think of multi-arch
        prefix = 'UC_X86_REG_'
        self.regs_names = {}
        for r in vars(ucc):
            if r.startswith(prefix):
                short = r[len(prefix):]
                self.regs_names[short] = getattr(ucc, r)

    def hook_mem_access(uc, access, address, size, value, user_data):
        log.info(f">>> Tracing MEM {access} {address} {size}")
        if access == UC_MEM_WRITE:
            log.info(">>> Memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" \
                    %(address, size, value))
        else:   # READ
            log.info(">>> Memory is being READ at 0x%x, data size = %u" \
                    %(address, size))

    def hook_code64(uc, address, size, user_data):
        log.info(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
        rip = uc.reg_read(ucc.UC_X86_REG_RIP)
        log.info(">>> RIP is 0x%x" %rip)

    def eval(self, **kwargs):
        """
        Evaluation by default

            TODO:
            - take register value / option thru kwargs
            - handle hooks to easily get delta memory update after running
        """
        BASE = 0x401000 # FIXME: Create a configuation feature for Ninjasm
        self.uc.mem_map(BASE, 2 * 1024 * 1024)
        # Map kwargs as REGISTER
        for k in kwargs.keys():
            if k in self.regs_names:
                self.uc.reg_write(self.regs_names[k], kwargs[k])
        if 'RSP' not in kwargs:
            self.uc.reg_write(ucc.UC_X86_REG_RSP, BASE + 0x200000)
        code = self.to_bytes()
        self.uc.mem_write(BASE, code)
        # flush all register if not set
        skip_registers = ['INVALID', 'IDTR', 'GDTR', 'LDTR', 'TR', 'MSR']
        for r, rid in self.regs_names.items():
            if r in skip_registers or r[0] == 'F':
                continue
            if r not in kwargs:
                self.uc.reg_write(rid, 0)
        # HOOKS
        self.uc.hook_add(UC_HOOK_CODE, Asm.hook_code64, None, BASE, BASE + len(code))
        self.uc.hook_add(UC_HOOK_MEM_WRITE, Asm.hook_mem_access)
        self.uc.hook_add(UC_HOOK_MEM_READ, Asm.hook_mem_access)
        self.uc.emu_start(BASE, BASE + len(code))

        self.regs_values = {}
        for r, v in self.regs_names.items():
            if r in skip_registers or r[0] == 'F':
                continue
            self.regs_values[r] = self.uc.reg_read(v)
