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

    def handle_function(self, cols):
        from ninjasm.parser import PythonBeginFunction, PythonEndFunction
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
                without_return = False
                # FIXME: how to handle no returning functions? must use annotation!?
                if self.ls_code[last_func[-1]].fname == '__init__':
                    without_return = True
                res.append(PythonEndFunction(last_indent, without_return))
                last_func.pop()
            res.append(code)
        self.ls_code = res

    def generate(self, stage1='__output__.py', stage2='__final__.nja'):
        here = pl.Path('.').resolve()
        cols = self.handle_indent()
        self.handle_function(cols)
        with open(here / stage1, 'w') as f:
            txt = "__out__ = ''\n"
            for idx, code in enumerate(self.ls_code):
                sub = code.add_content()
                txt += sub
            txt += f"with open('{stage2}', 'w') as f:\n"
            txt += "    f.write(__out__)\n"
            f.write(txt)
