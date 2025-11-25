"""
Preprocessor for Ninjasm

This module handles the preprocessing phase where Ninjasm source code (.nja)
is parsed to distinguish Python code blocks from assembly instructions.

The preprocessor recognizes:
- Python code blocks (prefixed with ';>>')
- Python function definitions (with special handling)
- Python heredoc strings (multi-line strings)
- Assembly instructions
- Comments

The output is a list of code blocks that can be processed by the generator.
"""

import re
import logging

log = logging.getLogger(__name__)


class Indentable:
    """
    Base class for code blocks that track indentation.
    
    Indentation is crucial for Python code generation, as Python is
    whitespace-sensitive. This class tracks the indentation level of
    each code block.
    
    Attributes:
        lineno (int): Line number in source file
        content (str): Content of the code block
        indent (int): Number of spaces at start of line
        cols (int): Column width for indentation (e.g., 4 for 4-space tabs)
    """
    
    def __init__(self, lineno, content):
        """
        Initialize an indentable code block.
        
        Args:
            lineno (int): Line number in source
            content (str): Code content
        """
        self.lineno = lineno
        self.content = content
        self.indent = -1
        self.count_indent()
        self.cols = -1

    def count_indent(self):
        """
        Count the indentation level of this line.
        
        Returns:
            int: Number of leading spaces
            
        Raises:
            PreprocessorError: If tabs are found (tabs not allowed)
        """
        from .errors import PreprocessorError
        
        if self.indent != -1:
            return self.indent
        
        for idx, c in enumerate(self.content):
            if c == '\t':
                raise PreprocessorError(
                    "Tabs are not allowed in Ninjasm code",
                    line=self.lineno,
                    context="Please configure your editor to use spaces instead of tabs"
                )
            elif c != ' ':
                self.indent = idx
                return idx
        
        # Empty line or all spaces
        self.indent = len(self.content)
        return self.indent


class PythonCode(Indentable):
    """
    Represents a Python code block.
    
    Python code blocks are lines prefixed with ';>>' in the .nja file.
    These blocks are executed during the preprocessing stage to generate
    assembly code dynamically.
    
    Example in .nja file:
        ;>> for i in range(5):
        ;>>     print(f"nop  ; iteration {i}")
    """
    
    def __init__(self, lineno, content):
        """
        Initialize a Python code block.
        
        Args:
            lineno (int): Line number
            content (str): Python code
        """
        Indentable.__init__(self, lineno, content)

    def __repr__(self):
        """String representation for debugging."""
        return (f"|I:{self.indent}/C:{self.cols}/{type(self).__name__}:\n"
                f"{self.content}\n|\n")

    def add_content(self):
        """
        Generate Python code for this block.
        
        Returns:
            str: Python code with newline
        """
        return self.content + '\n'


class PythonBeginStr(PythonCode):
    """
    Marks the beginning of a Python heredoc string.
    
    Heredoc strings are multi-line f-strings in Python that can contain
    assembly code. They start with f''' or f\"\"\" and allow embedding
    assembly templates.
    
    Example:
        ;>> code = f'''
        mov rax, {value}
        ret
        ;>> '''
    """
    pass


class PythonEndStr(PythonCode):
    """
    Marks the end of a Python heredoc string.
    
    This is automatically inserted when the closing quotes are detected.
    """
    
    def __init__(self, lineno, close):
        """
        Initialize heredoc end marker.
        
        Args:
            lineno (int): Line number
            close (str): Closing quotes (''' or \"\"\")
        """
        PythonCode.__init__(self, lineno, f"{close}#endstr")


class PythonBeginFunction(PythonCode):
    """
    Marks the beginning of a Python function definition.
    
    Functions in Ninjasm are special because they can generate assembly
    code. The generator needs to track function boundaries to properly
    handle the __out__ variable used for collecting assembly output.
    
    Attributes:
        fname (str): Function name
        
    Example:
        ;>> def syscall(num, *args):
        ;>>     # function body
        ;>> #enddef
    """
    
    def __init__(self, lineno, content, fname):
        """
        Initialize function definition.
        
        Args:
            lineno (int): Line number
            content (str): Function definition line
            fname (str): Function name
        """
        PythonCode.__init__(self, lineno, content)
        self.fname = fname

    def __repr__(self):
        """String representation for debugging."""
        return (f"|I:{self.indent}/C:{self.cols}/{type(self).__name__}:\n"
                f"{self.content}\n|\n")

    def add_content(self):
        """
        Generate Python code for function definition.
        
        This adds the function definition line plus initialization of
        the __out__ variable used to collect assembly code.
        
        Returns:
            str: Python code for function start
        """
        onemore = 0
        if self.cols != -1:
            onemore = self.cols
        
        return (self.content + '\n' +
                ((self.indent + onemore) * ' ') + "__out__ = ''\n")


class PythonEndFunction(PythonCode):
    """
    Marks the end of a Python function.
    
    This is inserted automatically at the function's closing boundary.
    If the function generates assembly code, it adds a return statement
    for the __out__ variable.
    
    Attributes:
        without_return (bool): If True, don't add return statement
    """
    
    def __init__(self, indent, without_return=False):
        """
        Initialize function end marker.
        
        Args:
            indent (int): Indentation level
            without_return (bool): Whether to omit return statement
        """
        self.indent = indent
        self.without_return = without_return

    def __repr__(self):
        """String representation for debugging."""
        return f"|I:{self.indent}//{type(self).__name__}|\n"

    def add_content(self):
        """
        Generate Python code for function end.
        
        Returns:
            str: Return statement or empty line
        """
        if self.without_return:
            return '\n'
        return (self.indent * ' ') + 'return __out__\n'


def escape(txt):
    """
    Escape special characters for Python string literals.
    
    This ensures that assembly code containing special characters
    can be safely embedded in Python f-strings.
    
    Args:
        txt (str): Text to escape
        
    Returns:
        str: Escaped text
        
    Example:
        >>> escape("Hello\\nWorld")
        "Hello\\\\nWorld"
    """
    txt = txt.replace('\a', '\\a')
    txt = txt.replace('\b', '\\b')
    txt = txt.replace('\t', '\\t')
    txt = txt.replace('\n', '\\n')
    txt = txt.replace('\v', '\\v')
    txt = txt.replace('\r', '\\r')
    return txt


class AsmCode(Indentable):
    """
    Represents an assembly code line.
    
    Assembly lines are not prefixed with ';>>' and are treated as
    assembly instructions or directives. During code generation, these
    are converted to Python code that appends to the __out__ variable.
    
    Example in .nja file:
        mov rax, 42
        
    Generates:
        __out__ += f'mov rax, 42\\n'
    """
    
    def __init__(self, lineno, content):
        """
        Initialize assembly code block.
        
        Args:
            lineno (int): Line number
            content (str): Assembly code
        """
        Indentable.__init__(self, lineno, content)

    def __repr__(self):
        """String representation for debugging."""
        return (f"|I:{self.indent}/C:{self.cols}/{type(self).__name__}:\n"
                f"{self.content}\n|\n")

    def add_content(self):
        """
        Generate Python code that outputs this assembly line.
        
        The assembly content is embedded in an f-string so that Python
        variables can be interpolated into the assembly code.
        
        Returns:
            str: Python code that appends to __out__
            
        Example:
            For assembly line "mov rax, 42"
            Generates: __out__ += f'mov rax, 42\\n'
        """
        # Escape special characters
        escaped = escape(self.content.replace("'", '"'))
        return (self.indent * ' ') + f"""__out__ += f'{escaped}'\\n"""


class Builder:
    """
    Builder for creating code blocks from parsed matches.
    
    The Builder takes regex match results and constructs the appropriate
    code block objects (PythonCode, AsmCode, etc.).
    """
    
    def __init__(self):
        """Initialize the builder."""
        pass

    def build(self, lineno, groupdict):
        """
        Build a code block from a regex match.
        
        Args:
            lineno (int): Line number in source
            groupdict (dict): Named groups from regex match
            
        Returns:
            Indentable: Appropriate code block object
            
        Raises:
            PreprocessorError: If match doesn't correspond to any known pattern
        """
        from .errors import PreprocessorError
        
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
        
        raise PreprocessorError(
            f"Unable to classify code block",
            line=lineno,
            context=str(groupdict)
        )


class Parser:
    """
    Parser for Ninjasm source files.
    
    The parser uses regular expressions to identify and extract different
    types of code blocks from .nja files. It recognizes:
    - Python code blocks (;>> prefix)
    - Python function definitions
    - Heredoc strings
    - Assembly instructions
    - Comments
    
    The parser produces a list of code block objects that the generator
    can then process into executable Python code.
    
    Example usage:
        parser = Parser()
        blocks = parser.parse(source_code)
        for block in blocks:
            print(block.add_content())
    """
    
    def __init__(self):
        """
        Initialize the parser with regex patterns.
        
        The regex pattern is defined in PEG-like notation in comments:
        - stmts <- stmt* EOS
        - stmt <- python_end_str / python_begin_str / python_code / comment / asm_insn
        - python_end_str <- (''' | \"\"\") EOS
        - python_begin_str <- .* f(''' | \"\"\") EOS
        - python_code <- ';>> ' .* EOS
        - comment <- ';' .* EOS
        - asm_insn <- [^;]* comment? EOS
        """
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
        """
        Parse Ninjasm source content into code blocks.
        
        This method processes the entire source file and produces a list
        of code block objects representing the structure of the file.
        
        Args:
            content (str): Ninjasm source code
            
        Returns:
            list: List of code block objects (PythonCode, AsmCode, etc.)
            
        Raises:
            ParseError: If content cannot be parsed
            
        Example:
            >>> parser = Parser()
            >>> blocks = parser.parse(";>> x = 5\\nmov rax, {x}")
            >>> len(blocks)
            2
        """
        from .errors import ParseError
        
        stmts = []
        pos = 0
        b = Builder()
        lineno = 0
        
        log.info(f"Parsing {len(content)} characters")
        
        while pos != len(content):
            # Try to match a statement
            m = self.asm_parser.match(content, pos)
            
            if m is None:
                # Failed to parse - provide context
                context_start = max(0, pos - 50)
                context_end = min(len(content), pos + 50)
                context = content[context_start:context_end]
                
                raise ParseError(
                    "Failed to parse content",
                    line=lineno,
                    context=f"...{context}..."
                )
            
            # Build code block from match
            try:
                block = b.build(lineno, m.groupdict())
                stmts.append(block)
            except Exception as e:
                raise ParseError(
                    f"Failed to build code block: {e}",
                    line=lineno,
                    context=m.group(0)[:100]
                )
            
            # Advance position
            pos += len(m.group(0))
            lineno += 1
        
        log.info(f"Parsed {len(stmts)} code blocks")
        return stmts


# ============================================================================
# Helper Functions
# ============================================================================

def validate_indentation(stmts):
    """
    Validate that indentation is consistent throughout the code.
    
    This checks that all indentation uses the same unit (e.g., 4 spaces)
    and that indentation changes are logical.
    
    Args:
        stmts (list): List of code block objects
        
    Returns:
        bool: True if indentation is valid
        
    Raises:
        PreprocessorError: If indentation is inconsistent
    """
    from .errors import PreprocessorError
    
    indent_levels = set()
    
    for stmt in stmts:
        if stmt.indent > 0:
            indent_levels.add(stmt.indent)
    
    if not indent_levels:
        return True
    
    # Check that all indents are multiples of smallest indent
    min_indent = min(indent_levels)
    for level in indent_levels:
        if level % min_indent != 0:
            raise PreprocessorError(
                "Inconsistent indentation detected",
                context=f"Found indents: {sorted(indent_levels)}"
            )
    
    log.debug(f"Indentation validated: {min_indent} spaces per level")
    return True


def find_python_blocks(stmts):
    """
    Find all Python code blocks in statement list.
    
    Args:
        stmts (list): List of code blocks
        
    Returns:
        list: List of Python code blocks
    """
    return [s for s in stmts if isinstance(s, (PythonCode, PythonBeginFunction))]


def find_asm_blocks(stmts):
    """
    Find all assembly code blocks in statement list.
    
    Args:
        stmts (list): List of code blocks
        
    Returns:
        list: List of assembly code blocks
    """
    return [s for s in stmts if isinstance(s, AsmCode)]


def count_blocks_by_type(stmts):
    """
    Count code blocks by type.
    
    Args:
        stmts (list): List of code blocks
        
    Returns:
        dict: Counts by block type
    """
    counts = {}
    for stmt in stmts:
        block_type = type(stmt).__name__
        counts[block_type] = counts.get(block_type, 0) + 1
    return counts
