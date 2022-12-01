import pathlib as pl

class Generator:
    def __init__(self, ls_code):
        self.ls_code = ls_code

    def handle_indent(self):
        cols = -1
        for idx, code in enumerate(self.ls_code):
            # indent for pythoncode block
            if hasattr(code, 'count_space'):
                code.indent = code.count_space()
                print(f"COUNT SPACE {code.indent} on {type(code)} at idx {idx}")
            # otherwise indent from previous line
            if code.indent == -1:
                code.indent = self.ls_code[idx - 1].indent
            # take the indent level globally
            if code.indent != 0 and cols == -1:
                cols = code.indent
            print(f"COLS {cols}")
            # if we are following a python block that increase indent level
            if self.ls_code[idx - 1].content[-1] == ':':
                # no previous correctly indented level
                if cols == -1:
                    # force it to 4 space
                    cols = 4
                print(f"INDENT LEVEL {self.ls_code[idx - 1].indent} / {cols}")
                code.indent = self.ls_code[idx - 1].indent + cols
        return cols

    def handle_heredoc(self):
        from ninjasm.parser import PythonBeginStr, PythonEndStr, AsmCode, PythonCode
        res = []
        szcode = len(self.ls_code)
        idx = 0
        while True:
            if idx >= szcode:
                break
            code = self.ls_code[idx]
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
                        code = PythonCode(heredoc + (indent * ' ') + ncode.content)
                        idx = next_idx
                        break
                    elif type(ncode) is AsmCode:
                        print(f"ADD ASMCODE idx {next_idx}")
                        heredoc += ncode.content
                    next_idx += 1
            res.append(code)
            idx += 1
        self.ls_code = res

    def handle_function(self, cols):
        from ninjasm.parser import PythonBeginFunction, PythonEndFunction, AsmCode
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
            elif len(last_func) and hasattr(code, 'space') and code.space == self.ls_code[last_func[-1]].space:
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

    def generate(self, stage1='__output__.py', stage2='__final__.nja'):
        here = pl.Path('.').resolve()
        cols = self.handle_indent()
        self.handle_heredoc()
        self.handle_function(cols)
        print(f"LS CODE {self.ls_code}")
        with open(here / stage1, 'w') as f:
            txt = "__out__ = ''\n"
            for idx, code in enumerate(self.ls_code):
                sub = code.add_content()
                txt += sub
            txt += f"with open('{stage2}', 'w') as f:\n"
            txt += "    f.write(__out__)\n"
            f.write(txt)
