"""
Ninjasm Error Management System

Custom exceptions for better error handling and user feedback.
"""


class NinjasmError(Exception):
    """Base exception for all Ninjasm-related errors."""
    
    def __init__(self, message, line=None, column=None, context=None):
        """
        Initialize a Ninjasm error.
        
        Args:
            message (str): Error description
            line (int, optional): Line number where error occurred
            column (int, optional): Column number where error occurred
            context (str, optional): Code context around the error
        """
        self.message = message
        self.line = line
        self.column = column
        self.context = context
        super().__init__(self.format_message())
    
    def format_message(self):
        """Format the error message with location information."""
        parts = []
        
        if self.line is not None:
            if self.column is not None:
                parts.append(f"Line {self.line}, Column {self.column}")
            else:
                parts.append(f"Line {self.line}")
        
        parts.append(self.message)
        
        msg = ": ".join(parts)
        
        if self.context:
            msg += f"\n\nContext:\n{self.context}"
        
        return msg


class ParseError(NinjasmError):
    """Raised when parsing fails."""
    pass


class PreprocessorError(NinjasmError):
    """Raised during preprocessing phase."""
    pass


class AssemblyError(NinjasmError):
    """Raised during assembly phase."""
    pass


class DirectiveError(NinjasmError):
    """Raised when processing directives."""
    pass


class ResolutionError(NinjasmError):
    """Raised when symbols cannot be resolved."""
    pass


class EvaluationError(NinjasmError):
    """Raised during code evaluation with Unicorn."""
    pass


class ValidationError(NinjasmError):
    """Raised when input validation fails."""
    pass


class FileError(NinjasmError):
    """Raised for file-related errors."""
    pass


class ArchitectureError(NinjasmError):
    """Raised for architecture-specific issues."""
    pass


def format_context(content, position, context_lines=2):
    """
    Format code context around an error position.
    
    Args:
        content (str): Full content
        position (int): Position of error
        context_lines (int): Number of lines to show before/after
        
    Returns:
        str: Formatted context with error indicator
    """
    lines = content[:position].split('\n')
    line_num = len(lines)
    col_num = len(lines[-1]) if lines else 0
    
    all_lines = content.split('\n')
    start = max(0, line_num - context_lines - 1)
    end = min(len(all_lines), line_num + context_lines)
    
    context = []
    for i in range(start, end):
        prefix = ">>> " if i == line_num - 1 else "    "
        context.append(f"{prefix}{i+1:4d} | {all_lines[i]}")
        
        if i == line_num - 1:
            # Add error indicator
            context.append(f"         {' ' * col_num}^")
    
    return '\n'.join(context)


class ErrorCollector:
    """
    Collect multiple errors during compilation.
    
    Useful for showing all errors at once rather than stopping at first error.
    """
    
    def __init__(self):
        self.errors = []
        self.warnings = []
    
    def add_error(self, error):
        """Add an error to the collection."""
        self.errors.append(error)
    
    def add_warning(self, warning):
        """Add a warning to the collection."""
        self.warnings.append(warning)
    
    def has_errors(self):
        """Check if any errors were collected."""
        return len(self.errors) > 0
    
    def has_warnings(self):
        """Check if any warnings were collected."""
        return len(self.warnings) > 0
    
    def format_all(self):
        """Format all errors and warnings for display."""
        output = []
        
        if self.errors:
            output.append(f"\n{'='*60}")
            output.append(f"ERRORS ({len(self.errors)}):")
            output.append('='*60)
            for i, error in enumerate(self.errors, 1):
                output.append(f"\nError {i}:")
                output.append(str(error))
        
        if self.warnings:
            output.append(f"\n{'='*60}")
            output.append(f"WARNINGS ({len(self.warnings)}):")
            output.append('='*60)
            for i, warning in enumerate(self.warnings, 1):
                output.append(f"\nWarning {i}:")
                output.append(str(warning))
        
        return '\n'.join(output)
    
    def raise_if_errors(self):
        """Raise an exception if any errors were collected."""
        if self.has_errors():
            raise NinjasmError(self.format_all())
