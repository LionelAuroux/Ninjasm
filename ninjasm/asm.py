"""
Assembly Core for Ninjasm

This module provides the core assembly functionality including:
- Assembly instruction encoding (via Keystone)
- Cross-reference resolution
- Code evaluation (via Unicorn)
- Disassembly (via Capstone)

The module follows the yasm/nasm directive syntax for sections, globals, and data definitions.
"""

import re
import struct
from keystone import *
from capstone import *
from unicorn import *
from unicorn import x86_const as ucc
import logging

log = logging.getLogger(__name__)


class XRef:
    """
    Cross-reference tracking for symbols in assembly code.
    
    XRef objects track references to symbols (labels, variables) that need
    to be resolved to actual addresses during the linking phase.
    
    Attributes:
        symbol (bytes): The symbol name being referenced
        fullsymbol (bytes): Full symbol name including properties (e.g., 'msg.len')
        code (list): Machine code bytes for the instruction
        idx (int): Offset in memory where this reference occurs
        szinsn (int): Size of the instruction in bytes
        idxref (int): Index within instruction where reference value is stored
        value (int): Resolved value of the symbol
        section (str): Section name where this reference occurs
        resolved (bool): Whether this reference has been resolved
        is_relative (bool): Whether this is a relative reference (for jumps)
    """
    
    def __init__(self, symbol, idx=0, section='.text'):
        """
        Initialize a cross-reference.
        
        Args:
            symbol (bytes): Symbol name to reference
            idx (int): Memory offset of this reference
            section (str): Section containing this reference
        """
        self.symbol = symbol
        self.fullsymbol = symbol
        self.code = None
        self.idx = idx
        self.szinsn = 0
        self.idxref = 0
        self.value = None
        self.section = section
        self.resolved = False
        self.is_relative = False

    def __repr__(self):
        """String representation for debugging."""
        return (f"\n{self.fullsymbol.decode('utf-8', errors='replace')} "
                f"at {self.idx} size {self.szinsn} idxref {self.idxref}: {self.code}")

    def get_resolved(self, assembly, base_address):
        """
        Resolve the cross-reference to an actual address.
        
        This method calculates the actual bytes that should replace the
        placeholder in the instruction, based on the symbol's definition.
        
        Args:
            assembly (Asm): Assembly object containing symbol definitions
            base_address (int): Base address for absolute addressing
            
        Returns:
            list: Bytes to insert at the reference location
            
        Raises:
            ResolutionError: If symbol cannot be resolved
        """
        from errors import ResolutionError
        
        val = None
        self.resolved = True
        
        try:
            if hasattr(self, 'attr'):
                # Handle properties like 'msg.len'
                if self.attr == b'len':
                    if self.symbol not in assembly.defs:
                        raise ResolutionError(
                            f"Symbol '{self.symbol.decode()}' not defined",
                            context=f"Trying to access property '.{self.attr.decode()}'"
                        )
                    val = assembly.defs[self.symbol][b'len']
            else:
                # Handle regular symbols
                if self.symbol not in assembly.defs:
                    raise ResolutionError(
                        f"Undefined symbol: '{self.symbol.decode()}'",
                        context=f"Referenced at offset {self.idx} in section {self.section}"
                    )
                
                if not self.is_relative:
                    # Absolute addressing
                    val = assembly.defs[self.symbol][b'offs'] + base_address
                else:
                    # Relative addressing (for jumps/calls)
                    val = assembly.defs[self.symbol][b'offs'] - self.idx - self.szinsn
            
            # Determine number of bytes needed
            nbytes = self.szinsn - self.idxref
            log.info(f"Resolving {self.fullsymbol.decode()}: {val} as {nbytes} bytes")
            
            # Pack the value according to size
            fmt = None
            if nbytes == 8:
                fmt = 'q'  # signed long long
            elif nbytes == 4:
                fmt = 'i'  # signed int
            elif nbytes == 2:
                fmt = 'h'  # signed short
            elif nbytes == 1:
                fmt = 'b'  # signed byte
            else:
                raise ResolutionError(
                    f"Invalid reference size: {nbytes} bytes",
                    context=f"Symbol '{self.symbol.decode()}' at offset {self.idx}"
                )
            
            self.value = val
            return list(struct.pack(fmt, self.value))
            
        except KeyError as e:
            raise ResolutionError(
                f"Symbol definition incomplete: {e}",
                context=f"Symbol '{self.symbol.decode()}'"
            )
        except struct.error as e:
            raise ResolutionError(
                f"Failed to pack value {val}: {e}",
                context=f"Symbol '{self.symbol.decode()}', size={nbytes} bytes"
            )


class DirectiveParser:
    """
    Parser for Ninjasm assembly directives.
    
    This parser handles Ninjasm-specific directives like:
    - Data definitions (db, dw, dd, dq)
    - Reservations (resb, resw, resd, resq)
    - Labels
    - Sections
    - Global/extern declarations
    
    The parser uses regular expressions to match and extract directive
    components from assembly source code.
    """
    
    def __init__(self):
        """Initialize the directive parser with regex patterns."""
        # Complex regex for parsing various directive types
        directive_lang = rb"""(?mix)
        (?# Define directive: name? type values...
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
        
        # Regex for parsing constant values (int, float, strings)
        constant_lang = rb"""(?mix)
        \s*
        (?:
            (?: # float
                (?P<float_val>
                    (?: (?: \d+ \. \d*) | (?: \. \d+) )
                    (?: [eE] [+-]? \d+ )?
                )
            )
        |   (?:
                (?P<int_val>
                    (?:[1-9]+\d*) # decimal
                    | (?: 0[bB][01]+) # binary literal
                    | (?: 0[0-7]+(\. [0-7]+ ([pP] [+-]? \d+ )?)? ) # octal literal
                    | (?: 0[xX][0-9a-fA-F]+) # hexa literal
                )
            )
        | (?: ' (?P<qstr_val> (?: [^'\\] | \\. )* ) ' )
        | (?: " (?P<dqstr_val> (?: [^"\\] | \\. )* ) " )
        )\s*
        (?:;[^\n]+)? # extra comment
        """
        self.const_parser = re.compile(constant_lang)

    def parse(self, content):
        """
        Parse directive content and extract statements.
        
        Args:
            content (bytes): Content to parse
            
        Returns:
            int: Number of bytes successfully parsed
            
        Note:
            Results are stored in self.stmts and can be retrieved with get_stmts()
        """
        from errors import ParseError
        
        self.stmts = []
        pos = 0
        
        while pos < len(content):
            m = self.directive_parser.match(content, pos)
            
            if m is None:
                return 0
            
            stmt = m.groupdict()
            adv = len(m.group(0))
            
            # Special handling for define directives
            if 'define' in stmt and stmt['define'] is not None:
                stmt['values'] = []
                log.debug(f"Processing define directive at position {pos}")
                pos += adv
                
                # Parse list of constants
                while pos < len(content):
                    m = self.const_parser.match(content, pos)
                    
                    if m is None:
                        if content[pos] != ord(b'\n'):
                            # Try to match comma separator
                            p = re.compile(rb",[\s]*")
                            coma = p.match(content, pos)
                            if coma is not None:
                                pos += len(coma.group(0))
                        else:
                            break
                    else:
                        g = m.groupdict()
                        v = None
                        for t in ['float_val', 'int_val', 'qstr_val', 'dqstr_val']:
                            if g[t] is not None:
                                v = (t, g[t])
                                break
                        
                        if v is None:
                            raise ParseError(
                                "Invalid constant value in define directive",
                                context=content[pos:pos+20].decode('utf-8', errors='replace')
                            )
                        
                        stmt['values'].append(v)
                        pos += len(m.group(0))
            
            self.stmts.append(stmt)
            pos += adv
        
        log.debug(f"Parsed {len(self.stmts)} directive statements")
        return pos

    def get_stmts(self):
        """
        Get parsed statements.
        
        Returns:
            list: List of parsed directive dictionaries
        """
        return self.stmts


def handle_directive(assembly, directive):
    """
    Process a parsed directive and update assembly state.
    
    This function handles all supported directives including:
    - define: Data definitions (db, dw, etc.)
    - reserve: Space reservations (resb, resw, etc.)
    - label: Label definitions
    - section: Section changes
    - global/extern/static: Symbol visibility
    - origin: Origin address setting
    - default: Default addressing mode
    
    Args:
        assembly (Asm): Assembly object to update
        directive (dict): Parsed directive dictionary
        
    Raises:
        DirectiveError: If directive processing fails
    """
    from errors import DirectiveError
    
    log.debug(f"Handling directive: {directive}")
    
    try:
        if directive['define'] is not None:
            _handle_define(assembly, directive)
        elif directive['reserve'] is not None:
            _handle_reserve(assembly, directive)
        elif directive['label'] is not None:
            _handle_label(assembly, directive)
        elif directive['section'] is not None:
            _handle_section(assembly, directive)
        elif directive['global'] is not None:
            _handle_global(assembly, directive)
        elif directive['extern'] is not None:
            _handle_extern(assembly, directive)
        elif directive['static'] is not None:
            _handle_static(assembly, directive)
        elif directive['origin'] is not None:
            _handle_origin(assembly, directive)
        elif directive['default'] is not None:
            _handle_default(assembly, directive)
    except Exception as e:
        raise DirectiveError(
            f"Failed to process directive: {e}",
            context=str(directive)
        )


def _handle_define(assembly, directive):
    """Handle data definition directive (db, dw, dd, dq)."""
    from errors import DirectiveError
    
    df = directive['def_name']
    dt = directive['def_type']
    buf = []
    
    log.debug(f"Processing define: name={df}, type={dt}")
    
    if not directive['values']:
        raise DirectiveError(
            f"Define directive requires at least one value",
            context=f"Type: {dt.decode()}"
        )
    
    for t, v in directive['values']:
        try:
            if t == 'int_val':
                # Handle various number formats
                if v[0] == ord(b'0') and len(v) > 1:
                    if v[1] in b'xX':
                        v = int(v[2:], 16)
                    elif v[1] in b'bB':
                        v = int(v[2:], 2)
                    else:
                        v = int(v, 8)
                else:
                    v = int(v)
                buf.append(v)
                
            elif t == 'float_val':
                # Pack float as bytes
                buf.extend(struct.pack('f', float(v)))
                
            elif t in ('qstr_val', 'dqstr_val'):
                # String values as bytes
                buf.extend(list(v))
                
            else:
                raise DirectiveError(f"Unhandled value type: {t}")
                
        except (ValueError, struct.error) as e:
            raise DirectiveError(
                f"Invalid value for {dt.decode()}: {e}",
                context=f"Value: {v}"
            )
    
    begin = assembly.sections[assembly.current_section]['size']
    
    if df is None:
        # Continue previous definition
        if assembly.last_def is None:
            raise DirectiveError("Continuation define without initial name")
        assembly.upd_def(dt, buf)
    else:
        assembly.add_def(dt, df, buf, begin)
    
    # Update section
    assembly.sections[assembly.current_section]['opcodes'].extend(buf)
    assembly.sections[assembly.current_section]['size'] += len(buf)
    assembly.sections[assembly.current_section]['from_other'].update(
        range(begin, begin + len(buf))
    )


def _handle_reserve(assembly, directive):
    """Handle reservation directive (resb, resw, etc.)."""
    log.info("Reserve directive not yet implemented")
    # TODO: Implement reservation


def _handle_label(assembly, directive):
    """Handle label definition."""
    from errors import DirectiveError
    
    if directive['label_insn'] is not None:
        raise DirectiveError(
            "Labels with inline instructions not supported",
            context="Put the instruction on the next line"
        )
    
    ln = directive['label_name']
    offs = assembly.sections[assembly.current_section]['size']
    assembly.add_label(ln, offs)
    log.debug(f"Added label '{ln.decode()}' at offset {offs}")


def _handle_section(assembly, directive):
    """Handle section directive."""
    log.debug("Section directive handled")
    # Section handling is done during parsing


def _handle_global(assembly, directive):
    """Handle global symbol declaration."""
    log.debug("Global directive handled")
    # TODO: Track global symbols


def _handle_extern(assembly, directive):
    """Handle external symbol declaration."""
    log.debug("Extern directive handled")
    # TODO: Track external symbols


def _handle_static(assembly, directive):
    """Handle static symbol declaration."""
    log.debug("Static directive handled")
    # TODO: Track static symbols


def _handle_origin(assembly, directive):
    """Handle origin (org) directive."""
    log.debug("Origin directive handled")
    # TODO: Set origin address


def _handle_default(assembly, directive):
    """Handle default addressing mode."""
    log.debug("Default directive handled")
    # TODO: Set default addressing


def handle_decimal_value(insn):
    """
    Convert decimal numbers in instructions to hexadecimal.
    
    Keystone requires hexadecimal format for numeric literals.
    This function converts decimal numbers to hex format.
    
    Args:
        insn (bytes): Instruction bytes
        
    Returns:
        bytes: Instruction with decimal values converted to hex
        
    Example:
        >>> handle_decimal_value(b"mov rax, 100")
        b"mov rax, 0x64"
    """
    m = re.search(rb"(?i)(?P<int>(0[xb]?)?[1-9]\d*)", insn)
    
    if m is not None:
        num = m.groupdict()['int']
        log.debug(f"Converting number: {num}")
        
        if num[0] == ord('0') and len(num) > 1:
            if num[1] in [ord('x'), ord('X')]:
                # Already hex
                hexa = num[2:]
                insn = insn.replace(num, hexa)
            elif num[1] in [ord('b'), ord('B')]:
                # Binary to hex
                bnum = bytes(hex(int(num[2:], 2)), 'utf-8')
                insn = insn.replace(num, bnum)
            return insn
        
        # Decimal to hex
        hnum = bytes(hex(int(num)), 'utf-8')
        insn = insn.replace(num, hnum)
    
    return insn


class Asm:
    """
    Main assembly class for Ninjasm.
    
    This class orchestrates the entire assembly process:
    1. Parse and assemble instructions
    2. Track cross-references
    3. Resolve symbols
    4. Generate machine code
    5. Optionally evaluate code
    
    The class uses three powerful libraries:
    - Keystone: For assembling instructions to machine code
    - Capstone: For disassembling machine code back to assembly
    - Unicorn: For emulating and testing assembled code
    
    Attributes:
        content (str): Source assembly code
        xref (dict): Cross-reference table (symbol -> list of XRef)
        defs (dict): Symbol definitions (symbol -> {offs, len, bytes, type})
        sections (dict): Section data (name -> {opcodes, size, from_asm, from_other})
        current_section (str): Currently active section
        ks (Ks): Keystone assembler engine
        cs (Cs): Capstone disassembler engine  
        uc (Uc): Unicorn emulator engine
        
    Example:
        >>> asm = Asm("mov rax, 42\\nret")
        >>> asm.assemble()
        >>> asm.resolve()
        >>> code = asm.to_bytes()
    """
    
    def __init__(self, content):
        """
        Initialize the assembler.
        
        Args:
            content (str): Assembly source code
        """
        from errors import ArchitectureError
        
        self.content = content
        self.xref = {}
        self.last_xref = None
        self.last_def = None
        self.defs = {}
        self.dir_parse = DirectiveParser()
        
        try:
            self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
            self.ks.syntax = KS_OPT_SYNTAX_NASM
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
            self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        except Exception as e:
            raise ArchitectureError(f"Failed to initialize engines: {e}")
        
        self.current_section = ".text"
        self.sections = {
            ".text": {
                "opcodes": [],
                "size": 0,
                "from_asm": set(),
                "from_other": set()
            }
        }
        self.register_map()

    def add_label(self, lbl_name, offs):
        """
        Add a label definition.
        
        Args:
            lbl_name (bytes): Label name
            offs (int): Offset in current section
        """
        if lbl_name in self.defs:
            log.warning(f"Label '{lbl_name.decode()}' redefined")
        self.defs[lbl_name] = {b"offs": offs}
        log.debug(f"Label '{lbl_name.decode()}' -> offset {offs}")

    def add_def(self, def_type, def_name, buf, offs):
        """
        Add a data definition.
        
        Args:
            def_type (bytes): Type of definition (db, dw, etc.)
            def_name (bytes): Definition name
            buf (list): Data bytes
            offs (int): Offset in section
        """
        from errors import ValidationError
        
        if not def_name:
            raise ValidationError("Definition name cannot be empty")
        
        self.last_def = def_name
        self.defs[def_name] = {
            b"offs": offs,
            b"len": len(buf),
            b"bytes": buf,
            b"type": def_type
        }
        log.debug(f"Definition '{def_name.decode()}' -> {len(buf)} bytes at {offs}")

    def upd_def(self, def_type, buf):
        """
        Update (continue) the last definition.
        
        Args:
            def_type (bytes): Type of definition
            buf (list): Additional data bytes
            
        Raises:
            ValidationError: If types don't match or no previous definition
        """
        from errors import ValidationError
        
        if self.last_def is None:
            raise ValidationError("No previous definition to update")
        
        old_dt = self.defs[self.last_def][b'type']
        if def_type != old_dt:
            raise ValidationError(
                f"Type mismatch: trying to continue {old_dt.decode()} "
                f"with {def_type.decode()}"
            )
        
        self.defs[self.last_def][b"len"] += len(buf)
        self.defs[self.last_def][b"bytes"].extend(buf)
        log.debug(f"Updated '{self.last_def.decode()}' with {len(buf)} more bytes")

    def sym_resolver(self, symbol, value):
        """
        Keystone callback for symbol resolution.
        
        This is called by Keystone when it encounters an undefined symbol.
        We track it as a cross-reference to be resolved later.
        
        Args:
            symbol (bytes): Symbol name
            value (int): Placeholder value from Keystone
            
        Returns:
            bool: Always False to indicate symbol is not yet resolved
        """
        log.debug(f"Symbol resolver called for '{symbol.decode()}' = {value}")
        
        # Check if already defined (Keystone calls twice for labels)
        if symbol in self.xref and len(self.xref[symbol]) > 0:
            if self.xref[symbol][-1].idx == len(self.sections[self.current_section]['opcodes']):
                log.debug("Symbol already tracked, skipping")
                return False
        
        # Check for property access (e.g., 'msg.len')
        components = None
        if b'.' in symbol and symbol[0] != ord('.'):
            components = symbol.split(b'.')
            if len(components) > 2:
                from errors import ParseError
                raise ParseError(
                    f"Invalid symbol property: {symbol.decode()}",
                    context="Only one property level supported (e.g., 'symbol.len')"
                )
            symbol = components[0]
        
        xr = XRef(symbol, len(self.sections[self.current_section]['opcodes']), self.current_section)
        
        if components:
            xr.attr = components[1]
            xr.fullsymbol += b'.' + xr.attr
        
        if symbol not in self.xref:
            self.xref[symbol] = []
        
        self.last_xref = xr
        self.xref[symbol].append(xr)
        log.debug(f"Tracked XRef: {xr}")
        
        return False

    def get_insn(self, insn):
        """
        Assemble a single instruction.
        
        Args:
            insn (bytes): Instruction to assemble
            
        Returns:
            tuple: (code bytes, size)
            
        Raises:
            AssemblyError: If assembly fails
        """
        from errors import AssemblyError
        
        insn = insn.lstrip()
        
        try:
            code, cnt = self.ks.asm(handle_decimal_value(insn))
        except KsError as e:
            raise AssemblyError(
                f"Failed to assemble instruction: {e}",
                context=insn.decode('utf-8', errors='replace')
            )
        
        if code is None:
            raise AssemblyError(
                "Assembly produced no code",
                context=insn.decode('utf-8', errors='replace')
            )
        
        log.debug(f"Assembled: {insn} -> {cnt} bytes")
        
        if self.last_xref:
            self.last_xref.code = code
            self.last_xref.szinsn = len(code)
            
            # Find the placeholder bytes (zeros at end of instruction)
            pos = 0
            for pos, c in enumerate(reversed(code)):
                if c != 0:
                    break
            
            if pos == 0 and code[-1] != 0x0:
                log.warning("No placeholder found in instruction with XRef")
            
            self.last_xref.idxref = len(code) - pos
        
        return code, len(code)

    def assemble(self):
        """
        Assemble all instructions in the content.
        
        This is the main assembly method that:
        1. Sets up the symbol resolver
        2. Processes each line of assembly
        3. Handles directives and instructions
        4. Tracks cross-references
        
        Raises:
            AssemblyError: If assembly fails
        """
        from errors import AssemblyError
        
        log.info(f"Starting assembly of {len(self.content.split())} lines")
        
        self.ks.sym_resolver = self.sym_resolver
        self.sections[self.current_section]['opcodes'] = []
        self.sections[self.current_section]['size'] = 0
        
        for line_no, insn in enumerate(self.content.encode('utf-8').split(b'\n'), 1):
            self.last_xref = None
            insn = insn.strip()
            
            if insn == b"":
                continue
            
            log.debug(f"Line {line_no}: {insn}")
            
            try:
                # Try directive first
                pos = self.dir_parse.parse(insn)
                if pos != 0:
                    stmts = self.dir_parse.get_stmts()
                    for stmt in stmts:
                        handle_directive(self, stmt)
                    continue
                
                # Must be an instruction
                code, size = self.get_insn(insn)
                
            except KsError as e:
                if e.errno == KS_ERR_ASM_SYMBOL_MISSING:
                    # Handle undefined symbols
                    log.debug(f"Symbol missing in: {insn}")
                    
                    magic_value = b"0x00"
                    
                    # Special handling for jumps and calls
                    if insn[0] == ord(b'j'):
                        self.last_xref.is_relative = True
                        magic_value = b"0x02"
                    elif insn.startswith(b"call"):
                        self.last_xref.is_relative = True
                        magic_value = b"0x05"
                    
                    new_insn = insn.replace(self.last_xref.fullsymbol, magic_value)
                    code, size = self.get_insn(new_insn)
                else:
                    raise AssemblyError(
                        f"Assembly error: {e}",
                        line=line_no,
                        context=insn.decode('utf-8', errors='replace')
                    )
            
            # Add to section
            begin = self.sections[self.current_section]['size']
            self.sections[self.current_section]['opcodes'].extend(code)
            self.sections[self.current_section]['size'] += size
            self.sections[self.current_section]['from_asm'].update(range(begin, begin + size))
        
        log.info(f"Assembly complete: {self.sections[self.current_section]['size']} bytes")

    def resolve(self, base_address=0x401000):
        """
        Resolve all cross-references.
        
        This replaces placeholder values in instructions with actual addresses.
        
        Args:
            base_address (int): Base address for absolute addressing
            
        Raises:
            ResolutionError: If any symbol cannot be resolved
        """
        from errors import ResolutionError
        
        log.info(f"Resolving {len(self.xref)} symbols with base 0x{base_address:x}")
        
        unresolved = []
        
        for dn in self.defs.keys():
            if dn not in self.xref:
                continue
            
            log.debug(f"Resolving references to '{dn.decode()}'")
            
            for xr in self.xref[dn]:
                try:
                    resolved_bytes = xr.get_resolved(self, base_address)
                    
                    for idx, v in enumerate(resolved_bytes):
                        subidx = xr.idx + xr.idxref + idx
                        self.sections[xr.section]['opcodes'][subidx] = v
                        
                except ResolutionError as e:
                    unresolved.append((dn, e))
        
        if unresolved:
            msg = "Failed to resolve symbols:\n"
            for sym, err in unresolved:
                msg += f"  - {sym.decode()}: {err}\n"
            raise ResolutionError(msg)
        
        log.info("All symbols resolved successfully")

    def to_dbstr(self, section='.text', begin=0, end=None):
        """
        Convert bytes to 'db' directive string.
        
        Args:
            section (str): Section name
            begin (int): Start offset
            end (int): End offset
            
        Returns:
            str: Formatted 'db' directive
        """
        if end is None:
            end = self.sections[section]['size']
        
        hexastr = ", ".join([
            ("0x%02X" % it)
            for it in self.sections[section]['opcodes'][begin:end]
            if it is not None
        ])
        return f"db {hexastr}"

    def to_bytes(self, section='.text', begin=0, end=None):
        """
        Convert opcodes to bytes.
        
        Args:
            section (str): Section name
            begin (int): Start offset
            end (int): End offset
            
        Returns:
            bytes: Machine code bytes
        """
        if end is None:
            end = self.sections[section]['size']
        
        return b"".join([
            it.to_bytes(1, 'big')
            for it in self.sections[section]['opcodes'][begin:end]
        ])

    def to_asm(self, section='.text', for_asm=False):
        """
        Disassemble to assembly code.
        
        Args:
            section (str): Section to disassemble
            for_asm (bool): If True, include raw bytes as 'db' directives
            
        Returns:
            str: Assembly code
        """
        code = []
        pos = 0
        szcode = self.sections[section]['size']
        fa = self.sections[section]['from_asm']
        fo = self.sections[section]['from_other']
        
        # Track unresolved references
        unresolved_adr = {}
        for xrlist in self.xref.values():
            for xr in xrlist:
                if not xr.resolved:
                    unresolved_adr[xr.idx] = xr
        
        while pos < szcode:
            if pos in fa:
                # Disassemble instruction
                for insn in self.cs.disasm(self.to_bytes(section, begin=pos), 0):
                    raw_opstr = insn.op_str
                    
                    if pos in unresolved_adr:
                        # Replace magic value with symbol
                        magic_value = "0x00"
                        if insn.mnemonic[0] == ord(b'j'):
                            magic_value = "0x02"
                        elif insn.mnemonic == b"call":
                            magic_value = "0x05"
                        raw_opstr = raw_opstr.replace(
                            magic_value,
                            unresolved_adr[pos].fullsymbol.decode('utf-8')
                        )
                    
                    txtcode = f"{insn.mnemonic} {raw_opstr}"
                    
                    if for_asm:
                        dbstr = "db " + ", ".join([("0x%02X" % b) for b in insn.bytes])
                        txtcode = dbstr + " ;     " + txtcode
                    
                    code.append(txtcode)
                    pos += insn.size
                    break
            
            elif pos in fo:
                # Find end of data block
                end = None
                for idx in range(pos, szcode):
                    if idx not in fo:
                        end = idx
                        break
                else:
                    end = szcode
                
                code.append(self.to_dbstr(begin=pos, end=end))
                pos = end
            else:
                pos += 1
        
        return "\n".join(code)

    def register_map(self):
        """Build mapping of register names to Unicorn constants."""
        prefix = 'UC_X86_REG_'
        self.regs_names = {}
        for r in dir(ucc):
            if r.startswith(prefix):
                short = r[len(prefix):]
                self.regs_names[short] = getattr(ucc, r)

    @staticmethod
    def hook_mem_access(uc, access, address, size, value, user_data):
        """Unicorn hook for memory access tracing."""
        if access == UC_MEM_WRITE:
            log.debug(f"MEM WRITE @ 0x{address:x}, size={size}, value=0x{value:x}")
        else:
            log.debug(f"MEM READ @ 0x{address:x}, size={size}")

    @staticmethod
    def hook_code64(uc, address, size, user_data):
        """Unicorn hook for instruction tracing."""
        rip = uc.reg_read(ucc.UC_X86_REG_RIP)
        log.debug(f"INSN @ 0x{address:x}, size={size}, RIP=0x{rip:x}")

    def eval(self, **kwargs):
        """
        Evaluate assembled code using Unicorn emulator.
        
        This method emulates execution of the assembled code,
        useful for testing and debugging.
        
        Args:
            **kwargs: Register initial values (e.g., RAX=10, RBX=20)
            
        Raises:
            EvaluationError: If emulation fails
            
        Example:
            >>> asm = Asm("add rax, rbx")
            >>> asm.assemble()
            >>> asm.resolve()
            >>> asm.eval(RAX=10, RBX=20)
            >>> print(asm.regs_values['RAX'])  # Should be 30
        """
        from errors import EvaluationError
        
        BASE = 0x401000
        
        try:
            self.uc.mem_map(BASE, 2 * 1024 * 1024)
        except Exception as e:
            raise EvaluationError(f"Failed to map memory: {e}")
        
        # Set register values from kwargs
        for k, v in kwargs.items():
            if k in self.regs_names:
                self.uc.reg_write(self.regs_names[k], v)
        
        # Set default RSP if not provided
        if 'RSP' not in kwargs:
            self.uc.reg_write(ucc.UC_X86_REG_RSP, BASE + 0x200000)
        
        code = self.to_bytes()
        self.uc.mem_write(BASE, code)
        
        # Zero out other registers
        skip_registers = ['INVALID', 'IDTR', 'GDTR', 'LDTR', 'TR', 'MSR']
        for r, rid in self.regs_names.items():
            if r in skip_registers or r[0] == 'F':
                continue
            if r not in kwargs:
                self.uc.reg_write(rid, 0)
        
        # Install hooks
        self.uc.hook_add(UC_HOOK_CODE, Asm.hook_code64, None, BASE, BASE + len(code))
        self.uc.hook_add(UC_HOOK_MEM_WRITE, Asm.hook_mem_access)
        self.uc.hook_add(UC_HOOK_MEM_READ, Asm.hook_mem_access)
        
        try:
            self.uc.emu_start(BASE, BASE + len(code))
        except Exception as e:
            raise EvaluationError(f"Emulation failed: {e}")
        
        # Read final register values
        self.regs_values = {}
        for r, v in self.regs_names.items():
            if r in skip_registers or r[0] == 'F':
                continue
            self.regs_values[r] = self.uc.reg_read(v)
        
        log.info("Emulation complete")
