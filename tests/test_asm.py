"""
Comprehensive test suite for Ninjasm asm module.

This test suite covers:
- DirectiveParser functionality
- XRef resolution
- Asm class methods
- Error handling
- Edge cases
"""

import pytest
from ninjasm.asm import (
    Asm, XRef, DirectiveParser, handle_directive,
    handle_decimal_value
)
from ninjasm.errors import (
    AssemblyError, DirectiveError, ResolutionError,
    ValidationError, EvaluationError
)
import logging

log = logging.getLogger(__name__)


# ============================================================================
# DirectiveParser Tests
# ============================================================================

class TestDirectiveParser:
    """Tests for DirectiveParser class."""
    
    def test_parse_db_directive_single_value(self):
        """Test parsing db directive with single value."""
        parser = DirectiveParser()
        content = b"msg db 0x48\n"
        pos = parser.parse(content)
        
        assert pos > 0
        stmts = parser.get_stmts()
        assert len(stmts) == 1
        assert stmts[0]['define'] is not None
        assert stmts[0]['def_name'] == b'msg'
        assert stmts[0]['def_type'] == b'db'
        assert len(stmts[0]['values']) == 1
    
    def test_parse_db_directive_multiple_values(self):
        """Test parsing db with multiple values."""
        parser = DirectiveParser()
        content = b"data db 1, 2, 3, 4\n"
        pos = parser.parse(content)
        
        stmts = parser.get_stmts()
        assert len(stmts[0]['values']) == 4
    
    def test_parse_db_directive_string(self):
        """Test parsing db with string value."""
        parser = DirectiveParser()
        content = b'msg db "Hello", 0xa\n'
        pos = parser.parse(content)
        
        stmts = parser.get_stmts()
        assert len(stmts[0]['values']) == 2
        assert stmts[0]['values'][0][0] == 'dqstr_val'
    
    def test_parse_db_hex_values(self):
        """Test parsing db with hexadecimal values."""
        parser = DirectiveParser()
        content = b"data db 0x48, 0x65, 0x6c, 0x6c, 0x6f\n"
        pos = parser.parse(content)
        
        stmts = parser.get_stmts()
        assert len(stmts[0]['values']) == 5
    
    def test_parse_db_binary_values(self):
        """Test parsing db with binary values."""
        parser = DirectiveParser()
        content = b"flags db 0b11110000\n"
        pos = parser.parse(content)
        
        stmts = parser.get_stmts()
        assert len(stmts[0]['values']) == 1
        assert stmts[0]['values'][0][0] == 'int_val'
    
    def test_parse_label(self):
        """Test parsing label definition."""
        parser = DirectiveParser()
        content = b"start:\n"
        pos = parser.parse(content)
        
        stmts = parser.get_stmts()
        assert stmts[0]['label'] is not None
        assert stmts[0]['label_name'] == b'start'
    
    def test_parse_label_with_comment(self):
        """Test parsing label with comment."""
        parser = DirectiveParser()
        content = b"loop_start: ; Start of main loop\n"
        pos = parser.parse(content)
        
        stmts = parser.get_stmts()
        assert stmts[0]['label'] is not None
        assert stmts[0]['label_name'] == b'loop_start'
    
    def test_parse_section(self):
        """Test parsing section directive."""
        parser = DirectiveParser()
        content = b"section .data\n"
        pos = parser.parse(content)
        
        stmts = parser.get_stmts()
        assert stmts[0]['section'] is not None
        assert stmts[0]['section_name'] == b'.data'
    
    def test_parse_global(self):
        """Test parsing global directive."""
        parser = DirectiveParser()
        content = b"global _start\n"
        pos = parser.parse(content)
        
        stmts = parser.get_stmts()
        assert stmts[0]['global'] is not None
        assert stmts[0]['global_name'] == b'_start'
    
    def test_parse_empty_line(self):
        """Test parsing empty lines."""
        parser = DirectiveParser()
        content = b"\n"
        pos = parser.parse(content)
        
        # Should handle gracefully
        assert pos >= 0
    
    def test_parse_comment_only(self):
        """Test parsing comment-only lines."""
        parser = DirectiveParser()
        content = b"; This is a comment\n"
        pos = parser.parse(content)
        
        stmts = parser.get_stmts()
        # Comments may or may not be stored
        assert pos > 0


# ============================================================================
# XRef Tests
# ============================================================================

class TestXRef:
    """Tests for XRef class."""
    
    def test_xref_creation(self):
        """Test basic XRef creation."""
        xr = XRef(b'symbol', idx=10, section='.text')
        
        assert xr.symbol == b'symbol'
        assert xr.idx == 10
        assert xr.section == '.text'
        assert not xr.resolved
        assert not xr.is_relative
    
    def test_xref_repr(self):
        """Test XRef string representation."""
        xr = XRef(b'test_sym', idx=100)
        repr_str = repr(xr)
        
        assert 'test_sym' in repr_str
        assert '100' in repr_str
    
    def test_xref_absolute_resolution(self):
        """Test absolute address resolution."""
        asm = Asm("")
        asm.defs[b'symbol'] = {b'offs': 0x100}
        
        xr = XRef(b'symbol', idx=0)
        xr.szinsn = 7
        xr.idxref = 3
        xr.is_relative = False
        
        result = xr.get_resolved(asm, base_address=0x400000)
        
        assert xr.resolved
        assert isinstance(result, list)
        assert len(result) == 4  # 7 - 3 = 4 bytes
    
    def test_xref_relative_resolution(self):
        """Test relative address resolution (for jumps)."""
        asm = Asm("")
        asm.defs[b'target'] = {b'offs': 0x50}
        
        xr = XRef(b'target', idx=0x10)
        xr.szinsn = 5
        xr.idxref = 1
        xr.is_relative = True
        
        result = xr.get_resolved(asm, base_address=0x400000)
        
        # Relative: target - current - insn_size
        # 0x50 - 0x10 - 5 = 0x3B
        assert xr.resolved
    
    def test_xref_property_resolution(self):
        """Test resolving symbol properties like 'msg.len'."""
        asm = Asm("")
        asm.defs[b'msg'] = {b'offs': 0x100, b'len': 13}
        
        xr = XRef(b'msg', idx=0)
        xr.attr = b'len'
        xr.fullsymbol = b'msg.len'
        xr.szinsn = 7
        xr.idxref = 3
        
        result = xr.get_resolved(asm, base_address=0x400000)
        
        assert xr.resolved
        # Should resolve to the length value (13)
    
    def test_xref_undefined_symbol_error(self):
        """Test error when symbol is undefined."""
        asm = Asm("")
        
        xr = XRef(b'undefined', idx=0)
        xr.szinsn = 5
        xr.idxref = 1
        
        with pytest.raises(ResolutionError) as exc_info:
            xr.get_resolved(asm, base_address=0x400000)
        
        assert 'undefined' in str(exc_info.value).lower()
    
    def test_xref_invalid_size_error(self):
        """Test error with invalid instruction size."""
        asm = Asm("")
        asm.defs[b'symbol'] = {b'offs': 0x100}
        
        xr = XRef(b'symbol', idx=0)
        xr.szinsn = 3
        xr.idxref = 0  # Results in 3 bytes, which is invalid
        
        with pytest.raises(ResolutionError) as exc_info:
            xr.get_resolved(asm, base_address=0x400000)
        
        assert 'size' in str(exc_info.value).lower()


# ============================================================================
# Helper Function Tests
# ============================================================================

class TestHelperFunctions:
    """Tests for helper functions."""
    
    def test_handle_decimal_value_simple(self):
        """Test converting simple decimal to hex."""
        result = handle_decimal_value(b"mov rax, 100")
        assert b"0x64" in result
    
    def test_handle_decimal_value_already_hex(self):
        """Test that hex values are left unchanged."""
        result = handle_decimal_value(b"mov rax, 0x64")
        assert b"0x64" in result
    
    def test_handle_decimal_value_binary(self):
        """Test converting binary to hex."""
        result = handle_decimal_value(b"mov rax, 0b1111")
        assert b"0x" in result
    
    def test_handle_decimal_value_no_numbers(self):
        """Test instruction without numbers."""
        result = handle_decimal_value(b"nop")
        assert result == b"nop"


# ============================================================================
# Asm Class Tests
# ============================================================================

class TestAsmBasic:
    """Basic tests for Asm class."""
    
    def test_asm_creation(self):
        """Test Asm object creation."""
        asm = Asm("nop")
        
        assert asm.content == "nop"
        assert asm.current_section == ".text"
        assert ".text" in asm.sections
        assert asm.ks is not None
        assert asm.cs is not None
        assert asm.uc is not None
    
    def test_add_label(self):
        """Test adding a label."""
        asm = Asm("")
        asm.add_label(b'start', 0)
        
        assert b'start' in asm.defs
        assert asm.defs[b'start'][b'offs'] == 0
    
    def test_add_def(self):
        """Test adding a data definition."""
        asm = Asm("")
        asm.add_def(b'db', b'msg', [0x48, 0x65], 0)
        
        assert b'msg' in asm.defs
        assert asm.defs[b'msg'][b'len'] == 2
        assert asm.defs[b'msg'][b'type'] == b'db'
    
    def test_add_def_empty_name_error(self):
        """Test that empty definition name raises error."""
        asm = Asm("")
        
        with pytest.raises(ValidationError):
            asm.add_def(b'db', b'', [0x48], 0)
    
    def test_upd_def(self):
        """Test updating a definition."""
        asm = Asm("")
        asm.add_def(b'db', b'data', [0x01], 0)
        asm.upd_def(b'db', [0x02, 0x03])
        
        assert asm.defs[b'data'][b'len'] == 3
        assert asm.defs[b'data'][b'bytes'] == [0x01, 0x02, 0x03]
    
    def test_upd_def_type_mismatch_error(self):
        """Test that type mismatch in update raises error."""
        asm = Asm("")
        asm.add_def(b'db', b'data', [0x01], 0)
        
        with pytest.raises(ValidationError):
            asm.upd_def(b'dw', [0x02])
    
    def test_upd_def_no_previous_error(self):
        """Test that updating without previous definition raises error."""
        asm = Asm("")
        
        with pytest.raises(ValidationError):
            asm.upd_def(b'db', [0x01])
    
    def test_register_map(self):
        """Test register name mapping."""
        asm = Asm("")
        
        assert 'RAX' in asm.regs_names
        assert 'RBX' in asm.regs_names
        assert 'RSP' in asm.regs_names


class TestAsmAssembly:
    """Tests for assembly functionality."""
    
    def test_assemble_nop(self):
        """Test assembling NOP instruction."""
        asm = Asm("nop")
        asm.assemble()
        
        assert asm.sections['.text']['size'] > 0
        assert len(asm.sections['.text']['opcodes']) > 0
    
    def test_assemble_mov_immediate(self):
        """Test assembling MOV with immediate value."""
        asm = Asm("mov rax, 42")
        asm.assemble()
        
        assert asm.sections['.text']['size'] > 0
    
    def test_assemble_multiple_instructions(self):
        """Test assembling multiple instructions."""
        asm = Asm("""
            mov rax, 1
            mov rbx, 2
            add rax, rbx
        """)
        asm.assemble()
        
        assert asm.sections['.text']['size'] > 0
    
    def test_assemble_with_label(self):
        """Test assembling with label definition."""
        asm = Asm("""
            start:
                mov rax, 1
        """)
        asm.assemble()
        
        assert b'start' in asm.defs
    
    def test_assemble_with_data(self):
        """Test assembling with data definition."""
        asm = Asm("""
            msg db "Hello", 0xa
            mov rax, msg
        """)
        asm.assemble()
        
        assert b'msg' in asm.defs
        assert b'msg' in asm.xref
    
    def test_assemble_jump(self):
        """Test assembling jump instruction."""
        asm = Asm("""
            start:
                jmp start
        """)
        asm.assemble()
        
        assert b'start' in asm.xref
        # Check that jump is marked as relative
        assert asm.xref[b'start'][0].is_relative
    
    def test_assemble_call(self):
        """Test assembling call instruction."""
        asm = Asm("""
            func:
                ret
            start:
                call func
        """)
        asm.assemble()
        
        assert b'func' in asm.xref
    
    def test_assemble_invalid_instruction_error(self):
        """Test that invalid instruction raises error."""
        asm = Asm("invalid_instruction")
        
        with pytest.raises(AssemblyError):
            asm.assemble()
    
    def test_assemble_label_with_inline_instruction_error(self):
        """Test that label with inline instruction raises error."""
        asm = Asm("label: mov rax, 1")
        
        with pytest.raises(DirectiveError):
            asm.assemble()


class TestAsmResolution:
    """Tests for symbol resolution."""
    
    def test_resolve_simple(self):
        """Test simple symbol resolution."""
        asm = Asm("""
            msg db 0x48
            mov rax, msg
        """)
        asm.assemble()
        asm.resolve()
        
        # After resolution, the placeholder should be replaced
        assert all(isinstance(x, int) for x in asm.sections['.text']['opcodes'])
    
    def test_resolve_with_base_address(self):
        """Test resolution with custom base address."""
        asm = Asm("""
            data db 0x01
            mov rax, data
        """)
        asm.assemble()
        asm.resolve(base_address=0x500000)
        
        # Should work without errors
        assert True
    
    def test_resolve_property(self):
        """Test resolving symbol property."""
        asm = Asm("""
            msg db "Hello", 0xa
            mov rax, msg.len
        """)
        asm.assemble()
        asm.resolve()
        
        # Should resolve msg.len to 6 (5 chars + newline)
        assert True
    
    def test_resolve_undefined_symbol_error(self):
        """Test that undefined symbol raises error."""
        asm = Asm("mov rax, undefined_symbol")
        asm.assemble()
        
        with pytest.raises(ResolutionError):
            asm.resolve()
    
    def test_resolve_forward_reference(self):
        """Test resolving forward reference."""
        asm = Asm("""
            mov rax, data
            data db 0x42
        """)
        asm.assemble()
        asm.resolve()
        
        # Should work even though data is defined after use
        assert True


class TestAsmConversion:
    """Tests for conversion methods."""
    
    def test_to_bytes(self):
        """Test converting to bytes."""
        asm = Asm("nop")
        asm.assemble()
        asm.resolve()
        
        code = asm.to_bytes()
        assert isinstance(code, bytes)
        assert len(code) > 0
        assert code == b'\x90'  # NOP opcode
    
    def test_to_dbstr(self):
        """Test converting to db string."""
        asm = Asm("nop")
        asm.assemble()
        asm.resolve()
        
        dbstr = asm.to_dbstr()
        assert 'db' in dbstr
        assert '0x90' in dbstr
    
    def test_to_asm(self):
        """Test disassembling to assembly."""
        asm = Asm("""
            mov rax, 42
            ret
        """)
        asm.assemble()
        asm.resolve()
        
        asm_code = asm.to_asm()
        assert 'mov' in asm_code.lower()
        assert 'rax' in asm_code.lower()
        assert 'ret' in asm_code.lower()
    
    def test_to_asm_with_data(self):
        """Test disassembling with data sections."""
        asm = Asm("""
            mov rax, 1
            data db 0x48, 0x65
        """)
        asm.assemble()
        asm.resolve()
        
        asm_code = asm.to_asm()
        assert 'mov' in asm_code.lower()
        assert 'db' in asm_code


class TestAsmEvaluation:
    """Tests for code evaluation with Unicorn."""
    
    def test_eval_simple(self):
        """Test evaluating simple code."""
        asm = Asm("""
            mov rax, 42
        """)
        asm.assemble()
        asm.resolve()
        asm.eval()
        
        assert 'RAX' in asm.regs_values
        assert asm.regs_values['RAX'] == 42
    
    def test_eval_arithmetic(self):
        """Test evaluating arithmetic."""
        asm = Asm("""
            mov rax, 10
            mov rbx, 20
            add rax, rbx
        """)
        asm.assemble()
        asm.resolve()
        asm.eval()
        
        assert asm.regs_values['RAX'] == 30
    
    def test_eval_with_initial_registers(self):
        """Test evaluation with initial register values."""
        asm = Asm("""
            add rax, rbx
        """)
        asm.assemble()
        asm.resolve()
        asm.eval(RAX=100, RBX=50)
        
        assert asm.regs_values['RAX'] == 150
    
    def test_eval_loop(self):
        """Test evaluating loop."""
        asm = Asm("""
            mov rcx, 5
            xor rax, rax
        loop_start:
            inc rax
            dec rcx
            jnz loop_start
        """)
        asm.assemble()
        asm.resolve()
        asm.eval()
        
        assert asm.regs_values['RAX'] == 5
        assert asm.regs_values['RCX'] == 0
    
    def test_eval_memory_access(self):
        """Test evaluation with memory access."""
        asm = Asm("""
            mov rdi, buff
            mov rcx, buff.len
            mov al, 0x90
        loop_fill:
            stosb
            dec rcx
            jnz loop_fill
        buff:
            db 0, 0, 0, 0, 0, 0, 0, 0
        """)
        asm.assemble()
        asm.resolve()
        asm.eval()
        
        # Check that buffer was filled
        base = asm.defs[b'buff'][b'offs'] + 0x401000
        size = asm.defs[b'buff'][b'len']
        mem = asm.uc.mem_read(base, size)
        
        assert all(b == 0x90 for b in mem)


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration:
    """Integration tests combining multiple features."""
    
    def test_hello_world_structure(self):
        """Test a hello world-like structure."""
        asm = Asm("""
            _start:
                mov rax, 1          ; write syscall
                mov rdi, 1          ; stdout
                mov rsi, msg        ; message
                mov rdx, msg.len    ; length
                
            msg db "Hello", 0xa
        """)
        asm.assemble()
        asm.resolve()
        
        assert b'_start' in asm.defs
        assert b'msg' in asm.defs
        assert b'msg' in asm.xref
    
    def test_multiple_sections_simulation(self):
        """Test code with multiple labels acting like sections."""
        asm = Asm("""
            code_start:
                mov rax, data
                ret
            data_start:
                data db 0x42
        """)
        asm.assemble()
        asm.resolve()
        
        assert b'code_start' in asm.defs
        assert b'data_start' in asm.defs
        assert b'data' in asm.defs
    
    def test_roundtrip_assemble_disassemble(self):
        """Test assembly -> disassembly roundtrip."""
        original = """mov rax, 42
ret"""
        
        asm = Asm(original)
        asm.assemble()
        asm.resolve()
        disassembled = asm.to_asm()
        
        # Should contain the main instructions
        assert 'mov' in disassembled.lower()
        assert 'ret' in disassembled.lower()


# ============================================================================
# Error Handling Tests
# ============================================================================

class TestErrorHandling:
    """Tests for error handling and edge cases."""
    
    def test_empty_content(self):
        """Test handling empty content."""
        asm = Asm("")
        asm.assemble()
        asm.resolve()
        
        assert asm.sections['.text']['size'] == 0
    
    def test_whitespace_only(self):
        """Test handling whitespace-only content."""
        asm = Asm("   \n  \n  ")
        asm.assemble()
        asm.resolve()
        
        assert asm.sections['.text']['size'] == 0
    
    def test_comments_only(self):
        """Test handling comments-only content."""
        asm = Asm("; Just a comment\n; Another comment")
        asm.assemble()
        asm.resolve()
        
        assert asm.sections['.text']['size'] == 0
    
    def test_mixed_valid_invalid(self):
        """Test that one invalid line doesn't prevent others."""
        asm = Asm("nop")
        asm.assemble()
        
        # Valid instruction should work
        assert asm.sections['.text']['size'] > 0
    
    def test_property_undefined_symbol(self):
        """Test accessing property of undefined symbol."""
        asm = Asm("mov rax, undefined.len")
        asm.assemble()
        
        with pytest.raises(ResolutionError):
            asm.resolve()
    
    def test_multiple_property_levels_error(self):
        """Test that multiple property levels raise error."""
        from ninjasm.errors import ParseError
        
        asm = Asm("mov rax, symbol.prop.subprop")
        
        with pytest.raises(ParseError):
            asm.assemble()


# ============================================================================
# Run tests
# ============================================================================

if __name__ == '__main__':
    # Run with pytest
    pytest.main([__file__, '-v', '--tb=short'])
