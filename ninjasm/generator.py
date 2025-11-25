"""
Generator for Ninjasm

This module takes parsed code blocks from the preprocessor and generates
executable Python code. The generated Python code, when executed, produces
the final assembly (.asm) file.

The generator handles:
- Indentation management
- Heredoc string processing
- Function boundary detection
- Python syntax validation
- Code generation with proper __out__ variable handling
"""

import pathlib as pl
import ast
import logging

log = logging.getLogger(__name__)


class Generator:
    """
    Generator for converting parsed code blocks to executable Python.
    
    The generator processes code blocks from the preprocessor and creates
    a Python file that, when executed, generates the final assembly output.
    
    The generation process involves:
    1. Processing heredoc strings
    2. Calculating indentation levels
    3. Detecting function boundaries
    4. Validating Python syntax
    5. Writing the final Python file
    
    Attributes:
        ls_code (list): List of code block objects from preprocessor
        
    Example:
        >>> from ninjasm.preprocessor import Parser
        >>> from ninjasm.generator import Generator
        >>> 
        >>> parser = Parser()
        >>> blocks = parser.parse(source)
        >>> 
        >>> generator = Generator(blocks)
        >>> generator.generate('output.py', 'output.asm')
    """
    
    def __init__(self, ls_code):
        """
        Initialize the generator.
        
        Args:
            ls_code (list): List of code block objects
            
        Raises:
            ValidationError: If ls_code is invalid
        """
        from .errors import ValidationError
        
        if not isinstance(ls_code, list):
            raise ValidationError("ls_code must be a list of code blocks")
        
        self.ls_code = ls_code
        log.info(f"Generator initialized with {len(ls_code)} code blocks")

    def handle_syntax_error(self, fn):
        """
        Check for Python syntax errors in generated code.
        
        This method regenerates the Python code in a temporary format
        and uses Python's ast module to validate the syntax.
        
        Args:
            fn (str|Path): Filename for error reporting
            
        Returns:
            bool: True if syntax is valid, False otherwise
            
        Note:
            Syntax errors are printed to stdout for user feedback.
        """
        from .errors import PreprocessorError
        
        # Regenerate code for syntax checking
        txt = ""
        for c in self.ls_code:
            code = c.add_content()
            txt += code
        
        try:
            # Parse as Python AST
            ast.parse(txt, filename=str(fn))
            log.info("Python syntax validation passed")
            return True
            
        except SyntaxError as e:
            # Provide detailed syntax error information
            log.error(f"Syntax error detected: {e}")
            print(f"\nSYNTAX ERROR: {e}")
            print(f"  File: {e.filename}")
            print(f"  Line: {e.lineno}")
            print(f"  Offset: {e.offset}")
            
            if e.text:
                print(f"  Code: {e.text.rstrip()}")
                if e.offset:
                    print(f"        {' ' * (e.offset - 1)}^")
            
            # Show surrounding lines for context
            lines = txt.split('\n')
            if e.lineno:
                start = max(0, e.lineno - 3)
                end = min(len(lines), e.lineno + 2)
                
                print(f"\nContext:")
                for i in range(start, end):
                    prefix = ">>> " if i == e.lineno - 1 else "    "
                    print(f"{prefix}{i+1:4d} | {lines[i]}")
            
            return False

    def handle_indent(self):
        """
        Calculate and normalize indentation levels.
        
        This method:
        1. Finds the base indentation unit (e.g., 4 spaces)
        2. Sets proper indentation for assembly code based on context
        3. Adjusts assembly code indentation to match surrounding Python code
        
        Returns:
            int: Number of spaces per indentation level, or -1 if no indentation found
            
        Note:
            Assembly code inherits indentation from the previous block or
            increases by one level if following a Python line ending with ':'
        """
        cols = -1
        
        # Find base indentation unit
        for idx, code in enumerate(self.ls_code):
            if code.indent != 0 and cols == -1:
                cols = code.indent
                break
        
        log.debug(f"Base indentation: {cols} spaces")
        
        # Adjust assembly code indentation
        for idx, code in enumerate(self.ls_code):
            if type(code).__name__ == 'AsmCode':
                if idx == 0:
                    # First block stays at 0
                    code.indent = 0
                    continue
                
                previous = self.ls_code[idx - 1]
                
                if type(previous).__name__ == 'AsmCode':
                    # Inherit from previous assembly
                    code.indent = previous.indent
                    
                elif type(previous).__name__ in ('PythonCode', 'PythonBeginFunction'):
                    # Check if previous line ends with ':'
                    incr = 0
                    if previous.content.rstrip().endswith(':') and cols != -1:
                        incr = cols
                    code.indent = previous.indent + incr
        
        return cols

    def handle_heredoc(self):
        """
        Process heredoc strings (multi-line f-strings).
        
        Heredoc strings in Ninjasm allow embedding assembly code within
        Python f-strings. This method:
        1. Finds PythonBeginStr markers
        2. Collects all content until PythonEndStr
        3. Combines into a single PythonCode block
        
        The processed heredoc becomes a single f-string assignment.
        
        Example:
            ;>> code = f'''
            mov rax, {value}
            ;>> '''
            
        Becomes:
            code = f'''
            mov rax, {value}
            '''
        """
        from .errors import PreprocessorError
        
        res = []
        szcode = len(self.ls_code)
        idx = 0
        
        log.debug("Processing heredoc strings")
        
        while idx < szcode:
            code = self.ls_code[idx]
            
            if type(code).__name__ == 'PythonBeginStr':
                log.debug(f"Found heredoc start at index {idx}")
                
                # Start building heredoc content
                heredoc = code.content + "\n"
                next_idx = idx + 1
                found_end = False
                
                # Collect content until end marker
                while next_idx < szcode:
                    ncode = self.ls_code[next_idx]
                    
                    if type(ncode).__name__ == 'PythonEndStr':
                        log.debug(f"Found heredoc end at index {next_idx}")
                        
                        # Get proper indentation for closing quote
                        if next_idx > 0:
                            indent = self.ls_code[next_idx - 1].indent
                        else:
                            indent = 0
                        
                        # Create single code block for entire heredoc
                        from .preprocessor import PythonCode
                        code = PythonCode(
                            code.lineno,
                            heredoc + (indent * ' ') + ncode.content
                        )
                        
                        idx = next_idx
                        found_end = True
                        break
                        
                    elif type(ncode).__name__ == 'AsmCode':
                        # Add assembly line to heredoc
                        heredoc += ncode.content
                        
                    next_idx += 1
                
                if not found_end:
                    raise PreprocessorError(
                        "Unclosed heredoc string",
                        line=code.lineno,
                        context=f"Started at line {code.lineno}, no closing quotes found"
                    )
                
                log.debug(f"Heredoc processed: {len(heredoc)} characters")
            
            res.append(code)
            idx += 1
        
        self.ls_code = res
        log.info(f"Heredoc processing complete: {len(res)} blocks")

    def handle_function(self, cols):
        """
        Detect and mark function boundaries.
        
        Functions in Ninjasm need special handling because they use the
        __out__ variable to collect generated assembly code. This method:
        1. Finds function definitions (PythonBeginFunction)
        2. Tracks function scope based on indentation
        3. Inserts PythonEndFunction markers at function end
        4. Determines if function needs a return statement
        
        Args:
            cols (int): Number of spaces per indentation level
            
        Note:
            Functions without assembly code inside them don't get
            a return statement for __out__.
        """
        from .errors import PreprocessorError
        from .preprocessor import PythonEndFunction
        
        res = []
        last_func = []  # Stack of function start indices
        
        log.debug(f"Processing functions with {cols} space indentation")
        
        for idx, code in enumerate(self.ls_code):
            # Check for function start
            if type(code).__name__ == 'PythonBeginFunction':
                log.debug(f"Function '{code.fname}' starts at index {idx}")
                last_func.append(idx)
                code.cols = cols
            
            # Check for function end (dedent back to function level)
            elif len(last_func) and code.indent == self.ls_code[last_func[-1]].indent:
                func_start_idx = last_func[-1]
                
                # Determine if we need to return __out__
                without_return = True
                
                # Check if any assembly code exists between function start and here
                for subidx in range(idx - 1, func_start_idx, -1):
                    if type(self.ls_code[subidx]).__name__ == 'AsmCode':
                        log.debug(f"Assembly code found in function, adding return")
                        without_return = False
                        break
                
                # Get proper indentation for function body
                if func_start_idx + 1 < len(self.ls_code):
                    last_indent = self.ls_code[func_start_idx + 1].indent
                else:
                    last_indent = code.indent
                
                # Insert function end marker
                log.debug(f"Function ends at index {idx}, without_return={without_return}")
                res.append(PythonEndFunction(last_indent, without_return))
                last_func.pop()
            
            res.append(code)
        
        # Check for unclosed functions
        if last_func:
            func_idx = last_func[0]
            func_name = self.ls_code[func_idx].fname if hasattr(self.ls_code[func_idx], 'fname') else 'unknown'
            raise PreprocessorError(
                f"Unclosed function: '{func_name}'",
                line=self.ls_code[func_idx].lineno,
                context="Missing #enddef or dedent to close function"
            )
        
        self.ls_code = res
        log.info(f"Function processing complete: {len(res)} blocks")

    def generate(self, stage1=pl.Path('__output__.py'), stage2=pl.Path('__final__.asm')):
        """
        Generate the final Python file.
        
        This is the main method that orchestrates the entire generation process:
        1. Process heredoc strings
        2. Calculate indentation
        3. Process function boundaries
        4. Validate syntax
        5. Write Python file
        
        The generated Python file:
        - Initializes __out__ = ''
        - Contains all user code
        - Writes __out__ to the final .asm file
        
        Args:
            stage1 (Path): Output Python file path
            stage2 (Path): Final assembly file path
            
        Returns:
            bool: True if generation succeeded, False otherwise
            
        Raises:
            FileError: If file operations fail
            
        Example:
            >>> generator = Generator(code_blocks)
            >>> success = generator.generate(
            ...     stage1=Path('output.py'),
            ...     stage2=Path('output.asm')
            ... )
        """
        from .errors import FileError, PreprocessorError
        
        here = pl.Path('.').resolve()
        log.info(f"Starting code generation")
        log.debug(f"Stage 1 (Python): {stage1}")
        log.debug(f"Stage 2 (Assembly): {stage2}")
        
        try:
            # Step 1: Process heredoc strings
            log.info("Step 1/4: Processing heredoc strings")
            self.handle_heredoc()
            
            # Step 2: Calculate indentation
            log.info("Step 2/4: Calculating indentation")
            cols = self.handle_indent()
            log.debug(f"Indentation: {cols} spaces per level")
            
            # Step 3: Process functions
            log.info("Step 3/4: Processing function boundaries")
            self.handle_function(cols)
            
            # Step 4: Validate syntax
            log.info("Step 4/4: Validating Python syntax")
            if not self.handle_syntax_error(here / stage1.with_suffix('.nja')):
                raise PreprocessorError(
                    "Generated Python code has syntax errors",
                    context="Check the error messages above"
                )
            
            # Generate final Python file
            log.info("Writing Python file")
            try:
                with open(here / stage1, 'w') as f:
                    # Header
                    txt = "#" * 10 + ' GENERATED! DO NOT EDIT ' + "#" * 10 + '\n'
                    txt += "# This file was automatically generated by Ninjasm\n"
                    txt += "# Modifications will be overwritten on next build\n\n"
                    
                    # Initialize output variable
                    txt += "__out__ = ''\n\n"
                    
                    # Add all code blocks
                    for idx, code in enumerate(self.ls_code):
                        try:
                            sub = code.add_content()
                            txt += sub
                        except Exception as e:
                            raise PreprocessorError(
                                f"Failed to generate code for block {idx}: {e}",
                                line=code.lineno if hasattr(code, 'lineno') else None
                            )
                    
                    # Footer: write output to assembly file
                    txt += "\n" + "#" * 10 + ' END OF GENERATED CODE ' + "#" * 10 + '\n\n'
                    txt += "# Write generated assembly to file\n"
                    txt += f"with open('{stage2}', 'w') as f:\n"
                    txt += "    f.write(__out__)\n"
                    
                    f.write(txt)
                
                log.info(f"Successfully generated: {stage1}")
                return True
                
            except IOError as e:
                raise FileError(
                    f"Failed to write Python file: {e}",
                    context=f"Path: {stage1}"
                )
                
        except Exception as e:
            log.error(f"Generation failed: {e}")
            raise


# ============================================================================
# Utility Functions
# ============================================================================

def validate_code_blocks(ls_code):
    """
    Validate that code blocks are well-formed.
    
    Args:
        ls_code (list): List of code blocks
        
    Returns:
        bool: True if valid
        
    Raises:
        ValidationError: If validation fails
    """
    from .errors import ValidationError
    from .preprocessor import Indentable
    
    if not all(isinstance(block, Indentable) for block in ls_code):
        raise ValidationError("All code blocks must inherit from Indentable")
    
    return True


def print_code_structure(ls_code):
    """
    Print the structure of code blocks for debugging.
    
    Args:
        ls_code (list): List of code blocks
    """
    print("\nCode Structure:")
    print("=" * 60)
    
    for idx, block in enumerate(ls_code):
        block_type = type(block).__name__
        indent = getattr(block, 'indent', -1)
        content_preview = getattr(block, 'content', '')[:40].replace('\n', '\\n')
        
        print(f"{idx:3d}. [{block_type:20s}] indent={indent:2d} | {content_preview}")
    
    print("=" * 60)


def count_lines(ls_code):
    """
    Count total lines in code blocks.
    
    Args:
        ls_code (list): List of code blocks
        
    Returns:
        int: Total line count
    """
    return sum(block.content.count('\n') + 1 for block in ls_code)


def get_function_names(ls_code):
    """
    Extract all function names from code blocks.
    
    Args:
        ls_code (list): List of code blocks
        
    Returns:
        list: Function names
    """
    from preprocessor import PythonBeginFunction
    
    return [
        block.fname
        for block in ls_code
        if isinstance(block, PythonBeginFunction)
    ]
