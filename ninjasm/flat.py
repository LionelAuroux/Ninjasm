"""
Flat Module - Binary Data Stream Management

This module provides utilities for building binary data streams with support
for various number formats and encoding schemes commonly used in assembly.

The Flat class allows incremental building of binary data with automatic
format detection and conversion.
"""

import struct
import logging

log = logging.getLogger(__name__)


class Flat:
    """
    Binary data stream builder.
    
    Flat provides a convenient way to build binary data incrementally,
    similar to assembly data directives (db, dw, dd, etc.) but with
    Python's flexibility.
    
    The class handles:
    - Multiple number formats (decimal, hex, octal, binary)
    - Automatic size detection
    - Signed/unsigned conversion
    - String encoding
    
    Attributes:
        __bytes (bytearray): Internal byte storage
        
    Example:
        >>> f = Flat()
        >>> f.db(0x48)      # Hex
        >>> f.db('65')      # Decimal as string
        >>> f.db('6Ch')     # Hex with 'h' suffix (assembly style)
        >>> f.db('0b1101')  # Binary
        >>> data = f.bytes
    """
    
    def __init__(self):
        """Initialize an empty binary stream."""
        self.__bytes = bytearray()
        log.debug("Flat instance created")

    def _to_int(self, data):
        """
        Convert data to integer with format auto-detection.
        
        This method supports multiple formats:
        - int: Used directly
        - str with suffix 'b'/'B': Binary (e.g., '1101b')
        - str with suffix 'h'/'H': Hexadecimal (e.g., 'FAh')
        - str with prefix '0x'/'0X': Hexadecimal (e.g., '0xFF')
        - str with prefix '0o'/'0O': Octal (e.g., '0o77')
        - str with prefix '0b'/'0B': Binary (e.g., '0b1111')
        - str decimal: Decimal number (e.g., '255')
        
        Args:
            data (int|str): Data to convert
            
        Returns:
            int: Converted integer value
            
        Raises:
            ValidationError: If data format is invalid
            
        Example:
            >>> f = Flat()
            >>> f._to_int('0xFF')
            255
            >>> f._to_int('1111b')
            15
            >>> f._to_int('77h')
            119
        """
        from .errors import ValidationError
        
        d = None
        
        # Already an integer
        if type(data) is int:
            return data
        
        # String - need to parse
        if type(data) is str:
            try:
                # Check for assembly-style suffixes (FAh, 1010b)
                if len(data) > 1:
                    suffix = data[-1].lower()
                    
                    if suffix == 'b':
                        # Binary with 'b' suffix
                        log.debug(f"Parsing binary (suffix): {data}")
                        return int(data[:-1], 2)
                    
                    if suffix == 'h':
                        # Hexadecimal with 'h' suffix
                        log.debug(f"Parsing hex (suffix): {data}")
                        return int(data[:-1], 16)
                
                # Check for Python-style prefixes (0xFF, 0b1010, 0o77)
                if len(data) > 2:
                    prefix = data[:2].lower()
                    
                    if prefix == '0x':
                        # Hexadecimal
                        log.debug(f"Parsing hex (prefix): {data}")
                        return int(data[2:], 16)
                    
                    if prefix == '0o':
                        # Octal
                        log.debug(f"Parsing octal: {data}")
                        return int(data[2:], 8)
                    
                    if prefix == '0b':
                        # Binary
                        log.debug(f"Parsing binary (prefix): {data}")
                        return int(data[2:], 2)
                
                # Plain decimal
                log.debug(f"Parsing decimal: {data}")
                return int(data)
                
            except ValueError as e:
                raise ValidationError(
                    f"Invalid number format: '{data}'",
                    context=f"Supported formats: decimal, 0xFF, 0b1111, 0o77, FAh, 1010b"
                )
        
        raise ValidationError(
            f"Unsupported data type: {type(data).__name__}",
            context="Expected int or str"
        )

    def db(self, data):
        """
        Add a byte (8-bit value) to the stream.
        
        This method is equivalent to the assembly 'db' (define byte) directive.
        It accepts values in various formats and automatically converts them
        to a single byte.
        
        Args:
            data (int|str): Value to add (must fit in -128 to 255 range)
            
        Raises:
            ValidationError: If value doesn't fit in a byte
            
        Example:
            >>> f = Flat()
            >>> f.db(65)        # ASCII 'A'
            >>> f.db('0x42')    # ASCII 'B'
            >>> f.db('-1')      # 0xFF (signed)
            >>> print(f.bytes)
            b'AB\\xff'
        """
        from .errors import ValidationError
        
        d = self._to_int(data)
        
        # Check if value fits in a byte
        if -128 <= d <= 127:
            # Signed byte
            self.__bytes += struct.pack('b', d)
            log.debug(f"Added signed byte: {d}")
        elif 0 <= d <= 255:
            # Unsigned byte
            self.__bytes += struct.pack('B', d)
            log.debug(f"Added unsigned byte: {d}")
        else:
            raise ValidationError(
                f"Value {d} doesn't fit in a byte",
                context="Valid range: -128 to 255"
            )

    def dw(self, data):
        """
        Add a word (16-bit value) to the stream.
        
        Equivalent to assembly 'dw' (define word) directive.
        
        Args:
            data (int|str): Value to add (must fit in 16 bits)
            
        Raises:
            ValidationError: If value doesn't fit in a word
            
        Example:
            >>> f = Flat()
            >>> f.dw(0x1234)
            >>> f.dw('5678h')
        """
        from .errors import ValidationError
        
        d = self._to_int(data)
        
        if -32768 <= d <= 32767:
            self.__bytes += struct.pack('h', d)
            log.debug(f"Added signed word: {d}")
        elif 0 <= d <= 65535:
            self.__bytes += struct.pack('H', d)
            log.debug(f"Added unsigned word: {d}")
        else:
            raise ValidationError(
                f"Value {d} doesn't fit in a word",
                context="Valid range: -32768 to 65535"
            )

    def dd(self, data):
        """
        Add a double word (32-bit value) to the stream.
        
        Equivalent to assembly 'dd' (define doubleword) directive.
        
        Args:
            data (int|str): Value to add (must fit in 32 bits)
            
        Raises:
            ValidationError: If value doesn't fit in a dword
        """
        from .errors import ValidationError
        
        d = self._to_int(data)
        
        if -2147483648 <= d <= 2147483647:
            self.__bytes += struct.pack('i', d)
            log.debug(f"Added signed dword: {d}")
        elif 0 <= d <= 4294967295:
            self.__bytes += struct.pack('I', d)
            log.debug(f"Added unsigned dword: {d}")
        else:
            raise ValidationError(
                f"Value {d} doesn't fit in a dword",
                context="Valid range: -2147483648 to 4294967295"
            )

    def dq(self, data):
        """
        Add a quad word (64-bit value) to the stream.
        
        Equivalent to assembly 'dq' (define quadword) directive.
        
        Args:
            data (int|str): Value to add (must fit in 64 bits)
            
        Raises:
            ValidationError: If value doesn't fit in a qword
        """
        from .errors import ValidationError
        
        d = self._to_int(data)
        
        if -9223372036854775808 <= d <= 9223372036854775807:
            self.__bytes += struct.pack('q', d)
            log.debug(f"Added signed qword: {d}")
        elif 0 <= d <= 18446744073709551615:
            self.__bytes += struct.pack('Q', d)
            log.debug(f"Added unsigned qword: {d}")
        else:
            raise ValidationError(
                f"Value {d} doesn't fit in a qword",
                context="Valid range: -2^63 to 2^64-1"
            )

    def string(self, s, null_terminate=False, encoding='utf-8'):
        """
        Add a string to the stream.
        
        Args:
            s (str): String to add
            null_terminate (bool): If True, add null terminator
            encoding (str): Character encoding to use
            
        Raises:
            ValidationError: If encoding fails
            
        Example:
            >>> f = Flat()
            >>> f.string("Hello")
            >>> f.string("World", null_terminate=True)
        """
        from .errors import ValidationError
        
        try:
            encoded = s.encode(encoding)
            self.__bytes += encoded
            
            if null_terminate:
                self.__bytes += b'\x00'
            
            log.debug(f"Added string: {len(encoded)} bytes")
            
        except UnicodeEncodeError as e:
            raise ValidationError(
                f"Failed to encode string: {e}",
                context=f"String: '{s}', Encoding: {encoding}"
            )

    def align(self, boundary):
        """
        Align stream to specified boundary by adding padding.
        
        Args:
            boundary (int): Alignment boundary (must be power of 2)
            
        Raises:
            ValidationError: If boundary is not power of 2
            
        Example:
            >>> f = Flat()
            >>> f.db(0x01)
            >>> f.align(4)  # Pad to 4-byte boundary
        """
        from .errors import ValidationError
        
        if boundary <= 0 or (boundary & (boundary - 1)) != 0:
            raise ValidationError(
                f"Alignment boundary must be power of 2, got {boundary}"
            )
        
        current_size = len(self.__bytes)
        padding = (boundary - (current_size % boundary)) % boundary
        
        if padding > 0:
            self.__bytes += b'\x00' * padding
            log.debug(f"Added {padding} bytes of padding for {boundary}-byte alignment")

    def reserve(self, count, fill=0):
        """
        Reserve space by adding bytes.
        
        Equivalent to assembly 'resb' directive.
        
        Args:
            count (int): Number of bytes to reserve
            fill (int): Fill value (default: 0)
            
        Raises:
            ValidationError: If parameters are invalid
            
        Example:
            >>> f = Flat()
            >>> f.reserve(100)  # Reserve 100 zero bytes
        """
        from .errors import ValidationError
        
        if count < 0:
            raise ValidationError("Cannot reserve negative space")
        
        if not 0 <= fill <= 255:
            raise ValidationError(f"Fill value must be 0-255, got {fill}")
        
        self.__bytes += bytes([fill] * count)
        log.debug(f"Reserved {count} bytes (fill: 0x{fill:02X})")

    @property
    def bytes(self):
        """
        Get the binary data as immutable bytes.
        
        Returns:
            bytes: The accumulated binary data
        """
        return bytes(self.__bytes)

    @property
    def size(self):
        """
        Get the current size of the stream.
        
        Returns:
            int: Number of bytes in stream
        """
        return len(self.__bytes)

    def clear(self):
        """Clear all data from the stream."""
        self.__bytes = bytearray()
        log.debug("Stream cleared")

    def __len__(self):
        """Get length of stream."""
        return len(self.__bytes)

    def __repr__(self):
        """String representation for debugging."""
        preview = self.bytes[:16]
        hex_str = ' '.join(f'{b:02X}' for b in preview)
        suffix = '...' if len(self.__bytes) > 16 else ''
        return f"Flat({len(self.__bytes)} bytes: {hex_str}{suffix})"


# ============================================================================
# Utility Functions
# ============================================================================

def bytes_to_hex_string(data, bytes_per_line=16):
    """
    Convert bytes to formatted hex string.
    
    Args:
        data (bytes): Data to format
        bytes_per_line (int): Bytes per line in output
        
    Returns:
        str: Formatted hex dump
        
    Example:
        >>> data = b'Hello World'
        >>> print(bytes_to_hex_string(data, 8))
        48 65 6C 6C 6F 20 57 6F
        72 6C 64
    """
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i+bytes_per_line]
        hex_values = ' '.join(f'{b:02X}' for b in chunk)
        lines.append(hex_values)
    return '\n'.join(lines)


def hex_string_to_bytes(hex_str):
    """
    Convert hex string to bytes.
    
    Args:
        hex_str (str): Hex string (e.g., "48 65 6C 6C 6F" or "48656C6C6F")
        
    Returns:
        bytes: Converted bytes
        
    Raises:
        ValidationError: If hex string is invalid
        
    Example:
        >>> hex_string_to_bytes("48 65 6C 6C 6F")
        b'Hello'
    """
    from .errors import ValidationError
    
    # Remove spaces and common separators
    cleaned = hex_str.replace(' ', '').replace(',', '').replace(':', '')
    
    if len(cleaned) % 2 != 0:
        raise ValidationError("Hex string must have even number of characters")
    
    try:
        return bytes.fromhex(cleaned)
    except ValueError as e:
        raise ValidationError(f"Invalid hex string: {e}")


def create_pattern(byte_value, count):
    """
    Create a repeating byte pattern.
    
    Args:
        byte_value (int): Byte to repeat
        count (int): Number of repetitions
        
    Returns:
        bytes: Pattern bytes
        
    Example:
        >>> create_pattern(0x90, 10)  # 10 NOPs
        b'\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90'
    """
    from .errors import ValidationError
    
    if not 0 <= byte_value <= 255:
        raise ValidationError(f"Byte value must be 0-255, got {byte_value}")
    
    if count < 0:
        raise ValidationError("Count cannot be negative")
    
    return bytes([byte_value] * count)
