# Ninjasm

**Python + Assembly = Ninja Programming**

Ninjasm is an innovative assembly language that uses Python as a powerful macro preprocessor. It combines the low-level control of assembly with the flexibility and expressiveness of Python.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

## 🎯 Features

- **Python-Powered Macros**: Use full Python syntax for code generation
- **Assembly at Runtime**: Assemble instructions during build time with Keystone
- **Code Evaluation**: Test and debug with Unicorn CPU emulator
- **Disassembly Support**: Convert back to assembly with Capstone
- **Cross-Reference Resolution**: Automatic symbol and label resolution
- **Multiple Architectures**: Currently supports x86_64 (more coming soon)

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Syntax Guide](#syntax-guide)
- [Examples](#examples)
- [Architecture](#architecture)
- [API Reference](#api-reference)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- NASM (for final assembly, optional with future versions)

### Install from Source

```bash
git clone https://github.com/LionelAuroux/Ninjasm.git
cd Ninjasm
python3 -m build
pip install .
```

### Install Dependencies

Ninjasm relies on three powerful libraries:

```bash
pip install keystone-engine
pip install capstone
pip install unicorn
```

## 🎮 Quick Start

### Hello World

Create a file `hello.nja`:

```asm
;>> # Python code to define a syscall helper
;>> class Syscall:
;>>     def __init__(self, num, arity):
;>>         self.num = num
;>>         self.arity = arity
;>>     def __call__(self, *args):
            mov rax, {self.num}
;>>         for idx, arg in enumerate(args):
;>>             regs = ['rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9']
;>>             if idx < len(regs):
                    mov {regs[idx]}, {arg}
;>>         #endfor
            syscall
;>>     #enddef

;>> syswrite = Syscall(1, 3)
;>> sysexit = Syscall(60, 1)

section .text
    global _start
    _start:
        {syswrite(1, 'msg', 'msg.len')}
        {sysexit(0)}

section .data
    msg db "Hello, World!", 0xa
```

### Build and Run

```bash
# Process the .nja file
ninjasm hello.nja

# This creates:
# - hello.py   (generated Python)
# - hello.asm  (generated assembly)
# - hello.o    (object file)

# Link and execute
ld hello.o -o hello
./hello
```

Output:
```
Hello, World!
```

## 📖 Syntax Guide

### Python Code Blocks

Python code is prefixed with `;>>`:

```asm
;>> # This is Python code
;>> x = 42
;>> for i in range(5):
    nop  ; This is assembly (Python loop generates 5 NOPs)
;>> #endfor
```

### Python Functions

Define reusable assembly generators:

```asm
;>> def push_all(*regs):
;>>     for reg in regs:
        push {reg}
;>>     #endfor
;>> #enddef

;>> def pop_all(*regs):
;>>     for reg in reversed(regs):
        pop {reg}
;>>     #endfor
;>> #enddef

my_function:
    {push_all('rax', 'rbx', 'rcx')}
    ; function body
    {pop_all('rax', 'rbx', 'rcx')}
    ret
```

### Heredoc Strings

Multi-line assembly templates:

```asm
;>> def function_prologue(stack_size):
;>>     return f'''
        push rbp
        mov rbp, rsp
        sub rsp, {stack_size}
;>>     '''
;>> #enddef

my_func:
    {function_prologue(32)}
    ; function code
    leave
    ret
```

### Data Definitions

```asm
;>> # Various data formats
msg db "Hello", 0xa          ; String with newline
num db 0x42                  ; Hex byte
flags db 0b11110000          ; Binary byte
array db 1, 2, 3, 4, 5      ; Multiple values

;>> # Access properties
mov rax, msg.len             ; Length of msg
```

### Labels and References

```asm
start:
    jmp loop_start

loop_start:
    ; loop body
    jnz loop_start
    
    mov rax, data_section
    ret

data_section:
    db 0x01, 0x02, 0x03
```

## 💡 Examples

### Example 1: Loop Unrolling

```asm
;>> def unroll_add(count):
;>>     for i in range(count):
        add rax, {i}
;>>     #endfor
;>> #enddef

optimized_sum:
    xor rax, rax
    {unroll_add(10)}  ; Generates 10 add instructions
    ret
```

### Example 2: Conditional Code Generation

```asm
;>> import sys
;>> DEBUG = True

my_function:
    push rbp
    mov rbp, rsp
    
;>> if DEBUG:
    ; Debug code
    int3  ; Breakpoint
;>> #endif
    
    ; Function body
    mov rax, 42
    
    leave
    ret
```

### Example 3: Lookup Table Generation

```asm
;>> def gen_lookup_table(func, size):
;>>     return [func(i) for i in range(size)]

;>> squares = gen_lookup_table(lambda x: x*x, 16)

square_table:
;>> for val in squares:
    dq {val}
;>> #endfor
```

### Example 4: Meta-programming with Keystone

```asm
;>> from ninjasm.asm import Asm
;>> 
;>> # Generate shellcode at compile time
;>> shellcode = Asm("""
;>>     mov rax, 60
;>>     xor rdi, rdi
;>>     syscall
;>> """)
;>> shellcode.assemble()
;>> shellcode.resolve()

payload:
    {shellcode.to_asm()}
```

## 🏗️ Architecture

Ninjasm has a multi-stage compilation process:

```
┌─────────────┐
│  .nja file  │  Source code (Python + Assembly)
└──────┬──────┘
       │ 1. Preprocessor (preprocessor.py)
       │    Parse and identify code blocks
       ▼
┌─────────────┐
│ Code Blocks │  Structured representation
└──────┬──────┘
       │ 2. Generator (generator.py)
       │    Generate Python code
       ▼
┌─────────────┐
│   .py file  │  Executable Python
└──────┬──────┘
       │ 3. Python Interpreter
       │    Execute to generate assembly
       ▼
┌─────────────┐
│  .asm file  │  Pure assembly code
└──────┬──────┘
       │ 4. Assembler (asm.py or NASM)
       │    Assemble to machine code
       ▼
┌─────────────┐
│   .o file   │  Object file
└─────────────┘
```

### Module Overview

#### `preprocessor.py`
- **Purpose**: Parse `.nja` files and distinguish Python from assembly
- **Key Classes**: `Parser`, `PythonCode`, `AsmCode`
- **Output**: List of code block objects

#### `generator.py`
- **Purpose**: Generate executable Python from code blocks
- **Key Classes**: `Generator`
- **Features**: Indentation handling, function detection, heredoc processing
- **Output**: `.py` file that generates assembly

#### `asm.py`
- **Purpose**: Core assembly functionality
- **Key Classes**: `Asm`, `XRef`, `DirectiveParser`
- **Features**: Instruction encoding, symbol resolution, code evaluation
- **Libraries**: Keystone, Capstone, Unicorn

#### `flat.py`
- **Purpose**: Binary data stream builder
- **Key Classes**: `Flat`
- **Features**: Format conversion, data packing

#### `errors.py`
- **Purpose**: Centralized error handling
- **Key Classes**: `NinjasmError`, `AssemblyError`, `ParseError`, etc.

## 📚 API Reference

### Asm Class

```python
from ninjasm.asm import Asm

# Create assembler
asm = Asm("mov rax, 42\nret")

# Assemble to machine code
asm.assemble()

# Resolve symbols
asm.resolve(base_address=0x400000)

# Get bytes
code = asm.to_bytes()

# Disassemble back to assembly
asm_code = asm.to_asm()

# Evaluate with Unicorn
asm.eval(RAX=10, RBX=20)
print(asm.regs_values['RAX'])  # 30
```

### Flat Class

```python
from ninjasm.flat import Flat

# Build binary data
f = Flat()
f.db(0x48)           # Byte
f.dw(0x1234)         # Word
f.dd(0x12345678)     # Dword
f.dq(0x123456789ABCDEF0)  # Qword
f.string("Hello")    # String

# Get bytes
data = f.bytes
```

### Parser Class

```python
from ninjasm.preprocessor import Parser

# Parse .nja content
parser = Parser()
blocks = parser.parse(content)

# Blocks is a list of code objects
for block in blocks:
    print(block.add_content())
```

### Generator Class

```python
from ninjasm.generator import Generator

# Generate Python from blocks
gen = Generator(blocks)
success = gen.generate(
    stage1='output.py',
    stage2='output.asm'
)
```

## 🧪 Testing

Ninjasm includes a comprehensive test suite using pytest.

### Run All Tests

```bash
pytest test_ninjasm.py -v
```

### Run Specific Test Category

```bash
# Test directive parsing
pytest test_ninjasm.py::TestDirectiveParser -v

# Test assembly
pytest test_ninjasm.py::TestAsmAssembly -v

# Test resolution
pytest test_ninjasm.py::TestAsmResolution -v
```

### Test Coverage

```bash
pytest --cov=ninjasm --cov-report=html
```

### Example Test

```python
def test_simple_mov():
    """Test assembling a MOV instruction."""
    asm = Asm("mov rax, 42")
    asm.assemble()
    asm.resolve()
    
    code = asm.to_bytes()
    assert len(code) > 0
    
    # Disassemble and check
    asm_code = asm.to_asm()
    assert 'mov' in asm_code.lower()
    assert 'rax' in asm_code.lower()
```

## 🔧 Error Handling

Ninjasm provides detailed error messages with context:

```python
from ninjasm.asm import Asm
from ninjasm.errors import AssemblyError

try:
    asm = Asm("invalid_instruction")
    asm.assemble()
except AssemblyError as e:
    print(e)
    # Output:
    # Line 1: Failed to assemble instruction: ...
    # Context:
    #     1 | invalid_instruction
```

### Error Types

- `ParseError`: Parsing failures
- `PreprocessorError`: Preprocessing issues
- `AssemblyError`: Assembly failures
- `ResolutionError`: Symbol resolution problems
- `EvaluationError`: Code emulation failures
- `ValidationError`: Invalid input or state
- `FileError`: File I/O problems

## 🛠️ Advanced Features

### Compile-Time Evaluation

```asm
;>> from ninjasm.asm import Asm
;>> 
;>> # Compute at compile time
;>> code = Asm("mov rax, 10\nmov rbx, 20\nadd rax, rbx")
;>> code.assemble()
;>> code.resolve()
;>> code.eval()
;>> result = code.regs_values['RAX']  # 30

optimized:
    mov rax, {result}  ; Uses precomputed value
    ret
```

### Custom Directives

```asm
;>> def align(boundary):
;>>     from ninjasm.flat import Flat
;>>     f = Flat()
;>>     f.align(boundary)
;>>     return f.bytes.hex()

my_data:
    db 0x01
    {align(16)}  ; Pad to 16-byte boundary
    db 0x02
```

### Register Allocation

```asm
;>> class RegAllocator:
;>>     def __init__(self):
;>>         self.free = ['r8', 'r9', 'r10', 'r11', 'r12']
;>>         self.used = []
;>>     
;>>     def alloc(self):
;>>         if not self.free:
;>>             raise RuntimeError("No free registers")
;>>         reg = self.free.pop(0)
;>>         self.used.append(reg)
;>>         return reg
;>>     
;>>     def free_reg(self, reg):
;>>         self.used.remove(reg)
;>>         self.free.insert(0, reg)
;>> #endclass

;>> regs = RegAllocator()
;>> r1 = regs.alloc()
;>> r2 = regs.alloc()

    mov {r1}, 10
    mov {r2}, 20
    add {r1}, {r2}
```

## 🗺️ Roadmap

- [ ] **ELF Generation**: Direct `.o` file creation without external assembler
- [ ] **PE Support**: Windows executable generation
- [ ] **ARM64 Support**: Additional architecture support
- [ ] **Optimization Pass**: Peephole optimization
- [ ] **Macro Library**: Standard library of common patterns
- [ ] **Debug Symbols**: DWARF debugging information
- [ ] **LSP Server**: IDE integration with language server

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork the Repository**
2. **Create a Feature Branch**: `git checkout -b feature/amazing-feature`
3. **Add Tests**: Ensure your code is tested
4. **Follow Style Guide**: Use Python PEP 8
5. **Document**: Add docstrings and update README
6. **Commit**: `git commit -m 'Add amazing feature'`
7. **Push**: `git push origin feature/amazing-feature`
8. **Pull Request**: Open a PR with description

### Development Setup

```bash
# Clone repo
git clone https://github.com/LionelAuroux/Ninjasm.git
cd Ninjasm

# Install in development mode
pip install -e .

# Install dev dependencies
pip install pytest pytest-cov black flake8

# Run tests
pytest

# Format code
black ninjasm/

# Lint
flake8 ninjasm/
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

Ninjasm stands on the shoulders of giants:

- **[Keystone Engine](https://www.keystone-engine.org)**: Assembly to machine code
- **[Capstone Engine](https://www.capstone-engine.org)**: Disassembly
- **[Unicorn Engine](https://www.unicorn-engine.org)**: CPU emulation

## 📞 Contact

- **Author**: Lionel Auroux
- **GitHub**: [@LionelAuroux](https://github.com/LionelAuroux)
- **Project**: [Ninjasm](https://github.com/LionelAuroux/Ninjasm)

## 📚 Resources

- [Ninjasm Examples](test/)
- [NASM Documentation](https://www.nasm.us/docs.php)
- [x86-64 Reference](https://www.felixcloutier.com/x86/)
- [Keystone Assembler](http://www.keystone-engine.org/docs/)

---

**Made with ❤️ and Assembly**
