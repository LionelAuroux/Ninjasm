from keystone import *

class Asm:
    def __init__(self, content):
        self.content = content

    def sym_resolver(self, symbol, value):
        print(f"Must RESOLVE {symbol}")
        value = 2600
        return True

    def assemble(self):
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        ks.sym_resolver = self.sym_resolver
        encoding, count = [], 0
        try:
            encoding, count = ks.asm(self.content)
        except KsError as e:
            print(f"Error: {e}")
        bcode = ""
        for i in encoding:
            bcode += "%02x " % i
        print(f"<{self.content}> = [{bcode}]")
