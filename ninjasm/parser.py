"""
Parser for Ninjasm

    - Distinguish python code from ASM code.
    - Distinguish pure ASM INSN from Ninjasm directive
    - Ninjasm directive follow yasm/nasm section/global/db
"""

import re

class PythonCode:
    def __init__(self, content):
        self.content = content
        self.indent = -1
        self.space = -1

    def __repr__(self):
        return f"[pythoncode:\n{self.content}\n]\n"

    def count_space(self):
        if self.space != -1:
            return self.space
        for idx, c in enumerate(self.content):
            print(f"CHECK {idx} [{c}]")
            if c != ' ':
                print(f"found not space")
                self.space = idx
                return idx

    def add_content(self):
        return self.content + '\n'

class PythonBeginFunction(PythonCode):
    def __init__(self, content):
        PythonCode.__init__(self, content)
        self.cols = -1

    def __repr__(self):
        return f"[pythonbegincode:\n{self.content}\n]\n"

    def add_content(self):
        return (self.content + '\n'
                + ((self.indent + self.cols) * ' ') + "__out__ = ''\n"
            )

class PythonEndFunction(PythonCode):
    def __init__(self, indent):
        self.indent = indent
        self.space = -1

    def __repr__(self):
        return f"[pythonendcode]\n"

    def add_content(self):
        return (self.indent * ' ') + 'return __out__\n'

def escape(txt):
    txt = txt.replace('\a', '\\a')
    txt = txt.replace('\b', '\\b')
    txt = txt.replace('\t', '\\t')
    txt = txt.replace('\n', '\\n')
    txt = txt.replace('\v', '\\v')
    txt = txt.replace('\r', '\\r')
    return txt

class AsmCode:
    def __init__(self, content):
        self.content = content
        self.indent = -1

    def __repr__(self):
        return f"[asmcode:\n{self.content}\n]\n"

    def add_content(self):
        # FIXME: escaping? indent?
        return (' ' * self.indent) + f"""__out__ += f'""" + escape(self.content.replace("'", '"')) + """'\n"""

class Builder:
    def __init__(self):
        pass

    def build(self, groupdict):
        if groupdict['python_code'] is not None:
            return PythonCode(groupdict['code'])
        if groupdict['python_funcode'] is not None:
            return PythonBeginFunction(groupdict['fcode'])
        elif groupdict['asm_insn'] is not None:
            return AsmCode(groupdict['asm_insn'])
        elif groupdict['comment'] is not None:
            return AsmCode(groupdict['comment'])
        raise RuntimeError(f"Can't handle {groupdict}")

class Parser:
    def __init__(self):
        asm_lang = r"""(?umx)
        (?# Setup a Verbose, Unicode Regex
         # Due to some equivalence between PEG and regex formalism, let's describe our parser in PEG format
         #
         #  stmts <- stmt* EOS
         #  stmt <- python_code / comment EOS / asm_insn comment? EOS
         #  python_code <- ';>> ' .* EOS
         #  comment <- ';' .* EOS
         #  asm_insn <- [^;]* comment? EOS
        )
        (?P<python_funcode>;>>\s(?P<fcode>def\s+[^\n]*)\n)
        | (?P<python_code>;>>\s(?P<code>[^\n]*)\n)
        | (?P<comment>;(?!>>)[^\n]*\n)
        | (?P<asm_insn>[^;\n]*(?P<comment_asm_insn>;[^\n]*)?\n)
        """
        self.asm_parser = re.compile(asm_lang)

    def parse(self, content):
        # we will save statements in a list
        stmts = []
        # store last position
        pos = 0
        # read until end of content
        b = Builder()
        while pos != len(content):
            # try to parse something
            m = self.asm_parser.match(content, pos)
            # did we read something ?
            if m is None:
                raise ValueError(f"Failed to parse {content[pos:]}")
            # store the result
            stmts.append(b.build(m.groupdict()))
            # advance
            pos += len(m.group(0))
        return stmts
