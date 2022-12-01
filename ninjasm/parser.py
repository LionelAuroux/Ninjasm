"""
Preprocessor for Ninjasm

    FIXME: rename in preprocessor
    - Distinguish python code from ASM code.
    - TODO: Distinguish pure ASM INSN from Ninjasm directive
    - Ninjasm directive follow yasm/nasm section/global/db
"""

import re


class PythonCode:
    def __init__(self, content):
        print(f"Construct {type(content)}")
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

class PythonBeginStr(PythonCode):
    pass

class PythonEndStr(PythonCode):
    def __init__(self, close):
        PythonCode.__init__(self, f"{close}#endstr")

class PythonBeginFunction(PythonCode):
    def __init__(self, content, fname):
        PythonCode.__init__(self, content)
        self.fname = fname
        self.cols = -1

    def __repr__(self):
        return f"[pythonbegincode:\n{self.content}\n]\n"

    def add_content(self):
        return (self.content + '\n'
                + ((self.indent + self.cols) * ' ') + "__out__ = ''\n"
            )

class PythonEndFunction(PythonCode):
    def __init__(self, indent, without_return=False):
        self.indent = indent
        self.space = -1
        self.without_return = without_return

    def __repr__(self):
        return f"[pythonendcode]\n"

    def add_content(self):
        if self.without_return:
            return '\n'
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
        elif groupdict['python_funcode'] is not None:
            return PythonBeginFunction(groupdict['fcode'], groupdict['fname'])
        elif groupdict['python_begin_str'] is not None:
            return PythonBeginStr(groupdict['scode'])
        elif groupdict['python_end_str'] is not None:
            return PythonEndStr(groupdict['quotes'])
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
         #  stmt <- python_end_str / python_begin_str / python_code / comment / asm_insn
         #  python_end_str <- \("'''"|'\"\"\"'\) EOS
         #  python_begin_str <- .* f\("'''"|'\"\"\"'\) EOS
         #  python_code <- ';>> ' .* EOS
         #  comment <- ';' .* EOS
         #  asm_insn <- [^;]* comment? EOS
        )
        (?P<python_funcode>;>>\s(?P<fcode>\s*def\s+(?P<fname>\w+)[^\n]*)\n)
        | (?P<python_end_str>;>>\s+(?P<quotes>(?:'''|\"\"\"))\s*\n)
        | (?P<python_begin_str>;>>\s(?P<scode>[^\n]*(?<=f(?:'''|\"\"\")))\s*\n)
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
