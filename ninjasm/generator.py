"""
Generate Python code from Preprocessing Code Block
"""

import pathlib as pl
from ninjasm.preprocessor import *
import ast
import traceback as tb

class Generator:
    def __init__(self, ls_code):
        self.ls_code = ls_code

    def handle_syntax_error(self, fn):
        # regen in temporary file
        txt = ""
        for c in self.ls_code:
            code = c.add_content()
            txt += code
        try:
            ast.parse(txt, filename=fn)
        except SyntaxError as e:
            #tb.print_exc()
            print(f"SYNTAX ERROR : <{e}>")
            print(f"{vars(e)}")
            return False
        return True

    def handle_indent(self):
        cols = -1
        for idx, code in enumerate(self.ls_code):
            ## take the indent level globally
            if code.indent != 0 and cols == -1:
                cols = code.indent
            if type(code) is AsmCode:
                # assembly code keep same indent level than previous assembly code
                previous = self.ls_code[idx - 1]
                if type(previous) is AsmCode:
                    code.indent = previous.indent
                elif type(previous) is PythonCode:
                    incr = 0
                    if previous.content[-1] == ':' and cols != -1:
                        incr = cols
                    code.indent = previous.indent + incr
        return cols

    def handle_heredoc(self):
        res = []
        szcode = len(self.ls_code)
        idx = 0
        while True:
            if idx >= szcode:
                break
            code = self.ls_code[idx]
            print(f"HEREDOC {idx}: {code} : {type(code)}")
            if type(code) is PythonBeginStr:
                print(f"FOUND HEREDOC BEGIN STR")
                # handle heredoc
                heredoc = code.content + "\n"
                next_idx = idx
                while True:
                    if next_idx == szcode:
                        idx = next_idx
                        break
                    ncode = self.ls_code[next_idx]
                    print(f"TYPE {type(ncode)}")
                    if type(ncode) is PythonEndStr:
                        print(f"FOUND HEREDOC END STR {next_idx}")
                        indent = self.ls_code[next_idx - 1].indent
                        code = PythonCode(code.lineno, heredoc + (indent * ' ') + ncode.content)
                        idx = next_idx
                        break
                    elif type(ncode) is AsmCode:
                        print(f"ADD ASMCODE idx {next_idx}")
                        heredoc += ncode.content
                    next_idx += 1
                print(f"END HEREDOC with {code}")
            res.append(code)
            idx += 1
        self.ls_code = res

    def handle_function(self, cols):
        res = []
        last_func = []
        for idx, code in enumerate(self.ls_code):
            # check function begins
            if type(code) is PythonBeginFunction:
                # remember the last index (FIXME: no inline function)
                last_func.append(idx)
                # store the indent level
                code.cols = cols
            # check indent of function
            elif len(last_func) and code.indent == self.ls_code[last_func[-1]].indent:
                last_indent = self.ls_code[last_func[-1] + 1].indent
                without_return = True
                # FIXME: how to handle inline function
                # FIXME: check that #end is at same level than declaring function
                # FIXME: check than asmcode indent level is >= of indent level of last_beginning function
                # FIXME: at #end handle the value of an ignore_inside (-1 or value), that handle the indent level of last inside function
                # FIXME: check only asmcode between indent level of #end and the ignore_inside
                # check that no asmcode belongs to between here and beginning of function
                for subidx in range(idx, last_func[-1] + 1, -1):
                    print(f"CHECK subidx {subidx}")
                    if type(self.ls_code[subidx]) is AsmCode:
                        print(f"Found asmcode")
                        without_return = False
                        break
                print(f"APPEND END")
                res.append(PythonEndFunction(last_indent, without_return))
                last_func.pop()
            res.append(code)
        self.ls_code = res

    def generate(self, stage1=pl.Path('__output__.py'), stage2=pl.Path('__final__.asm')):
        here = pl.Path('.').resolve()
        print(f"LS CODE {self.ls_code}")
        self.handle_heredoc()
        print(f"HEREDOC OK")
        print(f"AFTER HEREDOC {self.ls_code}")
        cols = self.handle_indent()
        print(f"PRINT INDENT COLS {cols}")
        self.handle_function(cols)
        print(f"AFTER HFUN {self.ls_code}")
        print(f"HANDLE SYNTAX CHECK")
        if self.handle_syntax_error(here / stage1.with_suffix('.nja')):
            with open(here / stage1, 'w') as f:
                txt = "#" * 10 + 'GENERATED! DO NOT EDIT' + "#" * 10 + '\n'
                txt += "__out__ = ''\n"
                for idx, code in enumerate(self.ls_code):
                    sub = code.add_content()
                    txt += sub
                txt += "#" * 10 + 'END OF GENERATED' + "#" * 10 + '\n'
                txt += f"with open('{stage2}', 'w') as f:\n"
                txt += "    f.write(__out__)\n"
                f.write(txt)
            return True
        return False
