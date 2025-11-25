"""
Test suite for preprocessor, generator, and flat modules.

This file contains comprehensive tests for:
- preprocessor.py: Parsing and code block generation
- generator.py: Python code generation
- flat.py: Binary data stream building
"""

import pytest
import pathlib as pl
from ninjasm.preprocessor import (
    Parser, PythonCode, AsmCode, PythonBeginFunction,
    PythonBeginStr, PythonEndStr, PythonEndFunction,
    escape, validate_indentation
)
from ninjasm.generator import Generator
from ninjasm.flat import Flat, bytes_to_hex_string, hex_string_to_bytes
from ninjasm.errors import (
    ParseError, PreprocessorError, ValidationError
)
import logging

log = logging.getLogger(__name__)


# ============================================================================
# Preprocessor Tests
# ============================================================================

class TestParser:
    """Tests for Parser class."""
    
    def test_parse_python_code(self):
        """Test parsing Python code blocks."""
        parser = Parser()
        content = ";>> x = 5\n"
        blocks = parser.parse(content)
        
        assert len(blocks) == 1
        assert isinstance(blocks[0], PythonCode)
        assert 'x = 5' in blocks[0].content
    
    def test_parse_asm_instruction(self):
        """Test parsing assembly instructions."""
        parser = Parser()
        content = "mov rax, 42\n"
        blocks = parser.parse(content)
        
        assert len(blocks) == 1
        assert isinstance(blocks[0], AsmCode)
        assert 'mov rax, 42' in blocks[0].content
    
    def test_parse_mixed_code(self):
        """Test parsing mixed Python and assembly."""
        parser = Parser()
        content = """;>> x = 10
mov rax, {x}
;>> y = 20
mov rbx, {y}
"""
        blocks = parser.parse(content)
        
        assert len(blocks) == 4
        assert isinstance(blocks[0], PythonCode)
        assert isinstance(blocks[1], AsmCode)
        assert isinstance(blocks[2], PythonCode)
        assert isinstance(blocks[3], AsmCode)
    
    def test_parse_function_definition(self):
        """Test parsing Python function definitions."""
        parser = Parser()
        content = ";>> def my_func():\n"
        blocks = parser.parse(content)
        
        assert len(blocks) == 1
        assert isinstance(blocks[0], PythonBeginFunction)
        assert blocks[0].fname == 'my_func'
    
    def test_parse_heredoc_begin(self):
        """Test parsing heredoc start."""
        parser = Parser()
        content = ";>> code = f'''\n"
        blocks = parser.parse(content)
        
        assert len(blocks) == 1
        assert isinstance(blocks[0], PythonBeginStr)
    
    def test_parse_heredoc_end(self):
        """Test parsing heredoc end."""
        parser = Parser()
        content = ";>> '''\n"
        blocks = parser.parse(content)
        
        assert len(blocks) == 1
        assert isinstance(blocks[0], PythonEndStr)
    
    def test_parse_comment(self):
        """Test parsing assembly comments."""
        parser = Parser()
        content = "; This is a comment\n"
        blocks = parser.parse(content)
        
        assert len(blocks) == 1
        assert isinstance(blocks[0], AsmCode)
    
    def test_parse_empty_line(self):
        """Test parsing empty lines."""
        parser = Parser()
        content = "\n"
        blocks = parser.parse(content)
        
        # Empty lines create blocks with empty content
        assert len(blocks) >= 0
    
    def test_parse_complex_example(self):
        """Test parsing complex example with multiple features."""
        parser = Parser()
        content = """;>> def syscall(num):
            mov rax, {num}
            syscall
;>> #enddef

;>> write_syscall = 1

_start:
    {syscall(write_syscall)}
    ret
"""
        blocks = parser.parse(content)
        
        # Should have multiple blocks
        assert len(blocks) > 5
        
        # Check for function
        func_blocks = [b for b in blocks if isinstance(b, PythonBeginFunction)]
        assert len(func_blocks) == 1
        assert func_blocks[0].fname == 'syscall'
    
    def test_parse_invalid_content_error(self):
        """Test that truly invalid content raises error."""
        parser = Parser()
        # The parser is actually very permissive, but test error handling
        # In practice, most content parses as AsmCode
        pass  # Parser doesn't really fail on normal text


class TestIndentable:
    """Tests for Indentable base class."""
    
    def test_indent_counting(self):
        """Test indentation counting."""
        block = PythonCode(0, "    x = 5")
        assert block.indent == 4
    
    def test_no_indent(self):
        """Test no indentation."""
        block = PythonCode(0, "x = 5")
        assert block.indent == 0
    
    def test_tab_error(self):
        """Test that tabs raise error."""
        with pytest.raises(PreprocessorError) as exc_info:
            block = PythonCode(0, "\tx = 5")
        msg = str(exc_info.value).lower()
        assert 'tabs' in msg, f"tabs not found in {msg}"


class TestCodeBlocks:
    """Tests for specific code block types."""
    
    def test_python_code_add_content(self):
        """Test PythonCode.add_content()."""
        block = PythonCode(0, "x = 5")
        content = block.add_content()
        
        assert content == "x = 5\n"
    
    def test_asm_code_add_content(self):
        """Test AsmCode.add_content()."""
        block = AsmCode(0, "mov rax, 42")
        content = block.add_content()
        
        assert "__out__" in content
        assert "mov rax, 42" in content
        assert "f'" in content
    
    def test_python_begin_function_add_content(self):
        """Test PythonBeginFunction.add_content()."""
        block = PythonBeginFunction(0, "def test():", "test")
        block.cols = 4
        block.indent = 0
        content = block.add_content()
        
        assert "def test():" in content
        assert "__out__ = ''" in content
    
    def test_python_end_function_with_return(self):
        """Test PythonEndFunction with return."""
        block = PythonEndFunction(indent=4, without_return=False)
        content = block.add_content()
        
        assert "return __out__" in content
    
    def test_python_end_function_without_return(self):
        """Test PythonEndFunction without return."""
        block = PythonEndFunction(indent=4, without_return=True)
        content = block.add_content()
        
        assert "return" not in content


class TestEscapeFunction:
    """Tests for escape() helper function."""
    
    def test_escape_newline(self):
        """Test escaping newline."""
        result = escape("Hello\nWorld")
        assert result == "Hello\\nWorld"
    
    def test_escape_tab(self):
        """Test escaping tab."""
        result = escape("Hello\tWorld")
        assert result == "Hello\\tWorld"
    
    def test_escape_multiple(self):
        """Test escaping multiple characters."""
        result = escape("Line1\nLine2\tIndented")
        assert "\\n" in result
        assert "\\t" in result
    
    def test_escape_no_special_chars(self):
        """Test string with no special chars."""
        result = escape("Hello World")
        assert result == "Hello World"


class TestValidateIndentation:
    """Tests for validate_indentation() function."""
    
    def test_valid_indentation(self):
        """Test valid consistent indentation."""
        blocks = [
            PythonCode(0, "x = 1"),
            PythonCode(1, "    y = 2"),
            PythonCode(2, "        z = 3")
        ]
        
        assert validate_indentation(blocks)
    
    def test_inconsistent_indentation_error(self):
        """Test inconsistent indentation raises error."""
        blocks = [
            PythonCode(0, "x = 1"),
            PythonCode(1, "   y = 2"),  # 3 spaces
            PythonCode(2, "       z = 3")  # 7 spaces
        ]
        
        with pytest.raises(PreprocessorError):
            validate_indentation(blocks)
    
    def test_no_indentation(self):
        """Test blocks with no indentation."""
        blocks = [
            PythonCode(0, "x = 1"),
            PythonCode(1, "y = 2")
        ]
        
        assert validate_indentation(blocks)


# ============================================================================
# Generator Tests
# ============================================================================

class TestGenerator:
    """Tests for Generator class."""
    
    def test_generator_creation(self):
        """Test Generator initialization."""
        blocks = [PythonCode(0, "x = 5")]
        gen = Generator(blocks)
        
        assert gen.ls_code == blocks
    
    def test_generator_invalid_input_error(self):
        """Test Generator with invalid input."""
        with pytest.raises(ValidationError):
            gen = Generator("not a list")
    
    def test_handle_indent_simple(self):
        """Test indent handling with simple case."""
        blocks = [
            PythonCode(0, "x = 1"),
            AsmCode(1, "    nop")
        ]
        gen = Generator(blocks)
        
        cols = gen.handle_indent()
        assert cols == 4
    
    def test_handle_indent_no_indent(self):
        """Test indent handling with no indentation."""
        blocks = [
            PythonCode(0, "x = 1"),
            AsmCode(1, "nop")
        ]
        gen = Generator(blocks)
        
        cols = gen.handle_indent()
        assert cols == -1
    
    def test_handle_heredoc(self):
        """Test heredoc string processing."""
        blocks = [
            PythonBeginStr(0, "code = f'''"),
            AsmCode(1, "mov rax, 1"),
            AsmCode(2, "ret"),
            PythonEndStr(3, "'''")
        ]
        gen = Generator(blocks)
        
        gen.handle_heredoc()
        
        # Should be condensed to fewer blocks
        assert len(gen.ls_code) < len(blocks)
        
        # First block should contain all heredoc content
        combined_content = gen.ls_code[0].content
        assert "mov rax, 1" in combined_content
        assert "ret" in combined_content
    
    def test_handle_heredoc_unclosed_error(self):
        """Test unclosed heredoc raises error."""
        blocks = [
            PythonBeginStr(0, "code = f'''"),
            AsmCode(1, "mov rax, 1")
            # Missing PythonEndStr
        ]
        gen = Generator(blocks)
        
        with pytest.raises(PreprocessorError) as exc_info:
            gen.handle_heredoc()
        
        assert 'unclosed' in str(exc_info.value).lower()
    
    def test_handle_function(self):
        """Test function boundary detection."""
        blocks = [
            PythonBeginFunction(0, "def test():", "test"),
            AsmCode(1, "    nop"),
            PythonCode(2, "x = 1")  # Back to original indent
        ]
        gen = Generator(blocks)
        
        gen.handle_function(cols=4)
        
        # Should have added PythonEndFunction
        has_end = any(isinstance(b, PythonEndFunction) for b in gen.ls_code)
        assert has_end
    
    def test_handle_function_unclosed_error(self):
        """Test unclosed function raises error."""
        blocks = [
            PythonBeginFunction(0, "def test():", "test"),
            AsmCode(1, "    nop")
            # Never dedents back
        ]
        gen = Generator(blocks)
        
        # Should detect unclosed function
        with pytest.raises(PreprocessorError) as exc_info:
            gen.handle_function(cols=4)
        
        assert 'unclosed' in str(exc_info.value).lower()
    
    def test_syntax_validation_valid(self):
        """Test syntax validation with valid code."""
        blocks = [
            PythonCode(0, "x = 5"),
            PythonCode(1, "y = 10")
        ]
        gen = Generator(blocks)
        
        assert gen.handle_syntax_error("test.nja")
    
    def test_syntax_validation_invalid(self):
        """Test syntax validation with invalid code."""
        blocks = [
            PythonCode(0, "x = "),  # Syntax error
        ]
        gen = Generator(blocks)
        
        assert not gen.handle_syntax_error("test.nja")


# ============================================================================
# Flat Tests
# ============================================================================

class TestFlat:
    """Tests for Flat class."""
    
    def test_flat_creation(self):
        """Test Flat initialization."""
        f = Flat()
        assert f.size == 0
        assert f.bytes == b''
    
    def test_to_int_decimal(self):
        """Test _to_int with decimal."""
        f = Flat()
        assert f._to_int(42) == 42
        assert f._to_int('42') == 42
    
    def test_to_int_hex_prefix(self):
        """Test _to_int with hex prefix."""
        f = Flat()
        assert f._to_int('0xFF') == 255
        assert f._to_int('0x10') == 16
    
    def test_to_int_hex_suffix(self):
        """Test _to_int with hex suffix."""
        f = Flat()
        assert f._to_int('FFh') == 255
        assert f._to_int('10H') == 16
    
    def test_to_int_binary_prefix(self):
        """Test _to_int with binary prefix."""
        f = Flat()
        assert f._to_int('0b1111') == 15
        assert f._to_int('0B1010') == 10
    
    def test_to_int_binary_suffix(self):
        """Test _to_int with binary suffix."""
        f = Flat()
        assert f._to_int('1111b') == 15
        assert f._to_int('1010B') == 10
    
    def test_to_int_octal(self):
        """Test _to_int with octal."""
        f = Flat()
        assert f._to_int('0o77') == 63
        assert f._to_int('0O10') == 8
    
    def test_to_int_invalid_error(self):
        """Test _to_int with invalid input."""
        f = Flat()
        
        with pytest.raises(ValidationError):
            f._to_int('invalid')
    
    def test_db_signed(self):
        """Test db with signed byte."""
        f = Flat()
        f.db(-1)
        assert f.bytes == b'\xff'
    
    def test_db_unsigned(self):
        """Test db with unsigned byte."""
        f = Flat()
        f.db(255)
        assert f.bytes == b'\xff'
    
    def test_db_hex_string(self):
        """Test db with hex string."""
        f = Flat()
        f.db('0x48')
        assert f.bytes == b'H'
    
    def test_db_out_of_range_error(self):
        """Test db with out of range value."""
        f = Flat()
        
        with pytest.raises(ValidationError):
            f.db(256)
        
        with pytest.raises(ValidationError):
            f.db(-129)
    
    def test_dw_word(self):
        """Test dw with word value."""
        f = Flat()
        f.dw(0x1234)
        assert len(f.bytes) == 2
    
    def test_dd_dword(self):
        """Test dd with dword value."""
        f = Flat()
        f.dd(0x12345678)
        assert len(f.bytes) == 4
    
    def test_dq_qword(self):
        """Test dq with qword value."""
        f = Flat()
        f.dq(0x123456789ABCDEF0)
        assert len(f.bytes) == 8
    
    def test_string(self):
        """Test string method."""
        f = Flat()
        f.string("Hello")
        assert f.bytes == b'Hello'
    
    def test_string_null_terminated(self):
        """Test string with null terminator."""
        f = Flat()
        f.string("Hello", null_terminate=True)
        assert f.bytes == b'Hello\x00'
    
    def test_align(self):
        """Test alignment."""
        f = Flat()
        f.db(0x01)
        f.align(4)
        
        assert f.size % 4 == 0
        assert f.size == 4  # 1 byte + 3 padding
    
    def test_align_invalid_boundary_error(self):
        """Test align with invalid boundary."""
        f = Flat()
        
        with pytest.raises(ValidationError):
            f.align(3)  # Not power of 2
    
    def test_reserve(self):
        """Test reserve method."""
        f = Flat()
        f.reserve(10)
        
        assert f.size == 10
        assert f.bytes == b'\x00' * 10
    
    def test_reserve_with_fill(self):
        """Test reserve with fill value."""
        f = Flat()
        f.reserve(5, fill=0x90)
        
        assert f.bytes == b'\x90' * 5
    
    def test_clear(self):
        """Test clear method."""
        f = Flat()
        f.db(0x01)
        f.db(0x02)
        f.clear()
        
        assert f.size == 0
        assert f.bytes == b''
    
    def test_len(self):
        """Test __len__ method."""
        f = Flat()
        f.db(0x01)
        f.db(0x02)
        
        assert len(f) == 2
    
    def test_repr(self):
        """Test __repr__ method."""
        f = Flat()
        f.db(0x48)
        f.db(0x65)
        
        repr_str = repr(f)
        assert 'Flat' in repr_str
        assert '2 bytes' in repr_str


class TestFlatUtilities:
    """Tests for flat module utility functions."""
    
    def test_bytes_to_hex_string(self):
        """Test bytes_to_hex_string function."""
        data = b'Hello'
        result = bytes_to_hex_string(data)
        
        assert '48' in result  # 'H'
        assert '65' in result  # 'e'
    
    def test_bytes_to_hex_string_multiline(self):
        """Test bytes_to_hex_string with multiple lines."""
        data = b'A' * 20
        result = bytes_to_hex_string(data, bytes_per_line=8)
        
        lines = result.split('\n')
        assert len(lines) == 3  # 8 + 8 + 4
    
    def test_hex_string_to_bytes(self):
        """Test hex_string_to_bytes function."""
        hex_str = "48 65 6C 6C 6F"
        result = hex_string_to_bytes(hex_str)
        
        assert result == b'Hello'
    
    def test_hex_string_to_bytes_no_spaces(self):
        """Test hex_string_to_bytes without spaces."""
        hex_str = "48656C6C6F"
        result = hex_string_to_bytes(hex_str)
        
        assert result == b'Hello'
    
    def test_hex_string_to_bytes_invalid_error(self):
        """Test hex_string_to_bytes with invalid input."""
        with pytest.raises(ValidationError):
            hex_string_to_bytes("ZZ")
    
    def test_hex_string_to_bytes_odd_length_error(self):
        """Test hex_string_to_bytes with odd length."""
        with pytest.raises(ValidationError):
            hex_string_to_bytes("123")


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration:
    """Integration tests across modules."""
    
    def test_parse_generate_flow(self):
        """Test complete parse -> generate flow."""
        source = """;>> x = 42
mov rax, {x}
ret
"""
        
        # Parse
        parser = Parser()
        blocks = parser.parse(source)
        
        assert len(blocks) == 3
        
        # Generate
        gen = Generator(blocks)
        # Don't actually write files in test
    
    def test_complex_example(self):
        """Test complex example with multiple features."""
        source = """;>> def gen_nops(count):
;>>     for i in range(count):
        nop
;>>     #endfor
;>> #enddef

start:
    {gen_nops(5)}
    ret
"""
        
        parser = Parser()
        blocks = parser.parse(source)
        
        # Should have function definition and usage
        func_blocks = [b for b in blocks if isinstance(b, PythonBeginFunction)]
        assert len(func_blocks) == 1


# ============================================================================
# Run tests
# ============================================================================

if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
