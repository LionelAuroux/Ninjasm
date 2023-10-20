"""
Preprocessor for Ninjasm

    - Distinguish python code from ASM code and build Preprocessing Code Block.
"""

import re

class Indentable:
    def __init__(self, lineno, content):
        self.lineno = lineno
        self.content = content
        self.indent = -1
        self.count_indent()
        self.cols = -1

    def count_indent(self):
        if self.indent != -1:
            return self.indent
        for idx, c in enumerate(self.content):
            print(f"CHECK {idx} [{c}]")
            if c == '\t':
                raise RuntimeError("Don't mix tabulation and space in your code, change your editor configuration to avoid tabulation")
            elif c != ' ':
                print(f"found not indent")
                self.indent = idx
                return idx

class PythonCode(Indentable):
    def __init__(self, lineno, content):
        Indentable.__init__(self, lineno, content)

    def __repr__(self):
        return f"|I:{self.indent}/C:{self.cols}/{type(self).__name__}:\n{self.content}\n|\n"

    def add_content(self):
        return self.content + '\n'

class PythonBeginStr(PythonCode):
    pass

class PythonEndStr(PythonCode):
    def __init__(self, lineno, close):
        PythonCode.__init__(self, lineno, f"{close}#endstr")

class PythonBeginFunction(PythonCode):
    def __init__(self, lineno, content, fname):
        PythonCode.__init__(self, lineno, content)
        self.fname = fname

    def __repr__(self):
        return f"|I:{self.indent}/C:{self.cols}/{type(self).__name__}:\n{self.content}\n|\n"

    def add_content(self):
        onemore = 0
        if self.cols != -1:
            onemore = self.cols
        return (self.content + '\n'
                + ((self.indent + onemore) * ' ') + "__out__ = ''\n"
            )

class PythonEndFunction(PythonCode):
    def __init__(self, indent, without_return=False):
        self.indent = indent
        self.without_return = without_return

    def __repr__(self):
        return f"|I:{self.indent}//{type(self).__name__}|\n"

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

class AsmCode(Indentable):
    def __init__(self, lineno, content):
        Indentable.__init__(self, lineno, content)

    def __repr__(self):
        return f"|I:{self.indent}/C:{self.cols}/{type(self).__name__}:\n{self.content}\n|\n"

    def add_content(self):
        # FIXME: escaping?
        return (self.indent * ' ') + f"""__out__ += f'""" + escape(self.content.replace("'", '"')) + """'\n"""

class Builder:
    def __init__(self):
        pass

    def build(self, lineno, groupdict):
        if groupdict['python_code'] is not None:
            return PythonCode(lineno, groupdict['code'])
        elif groupdict['python_funcode'] is not None:
            return PythonBeginFunction(lineno, groupdict['fcode'], groupdict['fname'])
        elif groupdict['python_begin_str'] is not None:
            return PythonBeginStr(lineno, groupdict['scode'])
        elif groupdict['python_end_str'] is not None:
            return PythonEndStr(lineno, groupdict['quotes'])
        elif groupdict['asm_insn'] is not None:
            return AsmCode(lineno, groupdict['asm_insn'])
        elif groupdict['comment'] is not None:
            return AsmCode(lineno, groupdict['comment'])
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
         #  *TODO* python_dir <- ';>- ' .* EOS
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
        lineno = 0
        while pos != len(content):
            # try to parse something
            m = self.asm_parser.match(content, pos)
            # did we read something ?
            if m is None:
                raise ValueError(f"Failed to parse {content[pos:]}")
            # store the result
            stmts.append(b.build(lineno, m.groupdict()))
            # advance
            pos += len(m.group(0))
            lineno += 1
        return stmts
