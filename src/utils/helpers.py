"""
Helpers Module

This module provides common utility functions used throughout the
secure messaging application. These functions handle:
- Data encoding and decoding
- Timestamp operations
- File operations
- Logging setup

Author: Shared (All Team Members)
"""

import os
import base64
import time
import logging
from datetime import datetime, timezone
from typing import Union, Optional

from src.utils.constants import (
    TEXT_ENCODING,
    LOG_LEVEL,
    LOG_FORMAT,
    NONCE_SIZE
)


# =============================================================================
# ENCODING / DECODING FUNCTIONS
# =============================================================================

def bytes_to_base64(data: bytes) -> str:
    """
    Convert binary data to a Base64-encoded string.
    
    Args:
        data: Binary data to encode
        
    Returns:
        Base64-encoded string representation of the data
        
    Example:
        >>> bytes_to_base64(b'Hello')
        'SGVsbG8='
    """
    # LEARN: Binary data (like encrypted bytes) contains non-printable characters
    # LEARN: that can cause problems when sending over networks or storing in text files.
    # LEARN: Base64 converts binary to ASCII text using A-Z, a-z, 0-9, +, /, =
    # LEARN: The downside is the output is about 33% larger than the input.
    
    return base64.b64encode(data).decode(TEXT_ENCODING)


def base64_to_bytes(data: str) -> bytes:
    """
    Convert a Base64-encoded string back to binary data.
    
    Args:
        data: Base64-encoded string
        
    Returns:
        Original binary data
        
    Example:
        >>> base64_to_bytes('SGVsbG8=')
        b'Hello'
    """
    # LEARN: This reverses the Base64 encoding process
    # LEARN: First we encode the string to bytes (ASCII), then decode Base64
    
    return base64.b64decode(data.encode(TEXT_ENCODING))


def string_to_bytes(data: str) -> bytes:
    """
    Convert a string to bytes using UTF-8 encoding.
    
    Args:
        data: String to convert
        
    Returns:
        UTF-8 encoded bytes
    """
    # LEARN: Strings in Python 3 are Unicode, but cryptographic functions
    # LEARN: need bytes. UTF-8 encoding converts characters to their byte
    # LEARN: representation. For ASCII characters, it's 1 byte per character.
    
    return data.encode(TEXT_ENCODING)


def bytes_to_string(data: bytes) -> str:
    """
    Convert bytes to a string using UTF-8 decoding.
    
    Args:
        data: Bytes to convert
        
    Returns:
        UTF-8 decoded string
    """
    # LEARN: This reverses string_to_bytes()
    # LEARN: Only use this for data that was originally text, not binary data
    
    return data.decode(TEXT_ENCODING)


# =============================================================================
# TIMESTAMP FUNCTIONS
# =============================================================================

def get_timestamp() -> float:
    """
    Get the current Unix timestamp.
    
    Returns:
        Current time as seconds since Unix epoch (Jan 1, 1970)
        
    Example:
        >>> get_timestamp()
        1704067200.123456
    """
    # LEARN: Unix timestamp is a standard way to represent time as a single number
    # LEARN: It's timezone-independent and easy to compare mathematically
    # LEARN: time.time() returns a float with microsecond precision
    
    return time.time()


def get_timestamp_string() -> str:
    """
    Get the current timestamp as a formatted string.
    
    Returns:
        Timestamp in ISO 8601 format (YYYY-MM-DD HH:MM:SS)
    """
    # LEARN: Human-readable timestamps are useful for logs and display
    # LEARN: datetime.now(timezone.utc) gets current time in UTC timezone
    # LEARN: This avoids timezone confusion between different machines
    
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def is_timestamp_valid(timestamp: float, max_age_seconds: float) -> bool:
    """
    Check if a timestamp is within the acceptable age limit.
    
    This is used to prevent replay attacks by rejecting old messages.
    
    Args:
        timestamp: Unix timestamp to check
        max_age_seconds: Maximum allowed age in seconds
        
    Returns:
        True if timestamp is within acceptable range, False otherwise
    """
    # LEARN: Replay attack: Attacker captures a valid message and sends it again later
    # LEARN: By checking timestamps, we reject messages that are too old
    # LEARN: This only works if both parties have reasonably synchronized clocks
    
    current_time = get_timestamp()
    age = current_time - timestamp
    
    # LEARN: We also reject timestamps from the future (clock skew tolerance)
    # LEARN: A message from 5 minutes in the future is suspicious
    if age < -60:  # Allow 1 minute of clock skew
        return False
    
    return age <= max_age_seconds


# =============================================================================
# FILE OPERATIONS
# =============================================================================

def ensure_directory_exists(directory_path: str) -> None:
    """
    Create a directory if it doesn't already exist.
    
    Args:
        directory_path: Path to the directory to create
    """
    # LEARN: os.makedirs creates the directory and all parent directories
    # LEARN: exist_ok=True means don't raise an error if it already exists
    
    os.makedirs(directory_path, exist_ok=True)


def file_exists(file_path: str) -> bool:
    """
    Check if a file exists.
    
    Args:
        file_path: Path to the file to check
        
    Returns:
        True if file exists, False otherwise
    """
    return os.path.isfile(file_path)


def read_file_bytes(file_path: str) -> bytes:
    """
    Read the entire contents of a binary file.
    
    Args:
        file_path: Path to the file to read
        
    Returns:
        File contents as bytes
        
    Raises:
        FileNotFoundError: If the file doesn't exist
    """
    # LEARN: 'rb' mode opens file for reading in binary mode
    # LEARN: Always use binary mode for encrypted data, keys, certificates
    
    with open(file_path, 'rb') as f:
        return f.read()


def write_file_bytes(file_path: str, data: bytes) -> None:
    """
    Write binary data to a file.
    
    Args:
        file_path: Path to the file to write
        data: Binary data to write
    """
    # LEARN: 'wb' mode opens file for writing in binary mode
    # LEARN: This will overwrite any existing file
    
    # Ensure the directory exists
    ensure_directory_exists(os.path.dirname(file_path))
    
    with open(file_path, 'wb') as f:
        f.write(data)


def read_file_text(file_path: str) -> str:
    """
    Read the entire contents of a text file.
    
    Args:
        file_path: Path to the file to read
        
    Returns:
        File contents as string
    """
    # LEARN: 'r' mode opens file for reading in text mode
    # LEARN: encoding parameter ensures consistent handling across platforms
    
    with open(file_path, 'r', encoding=TEXT_ENCODING) as f:
        return f.read()


def write_file_text(file_path: str, data: str) -> None:
    """
    Write text data to a file.
    
    Args:
        file_path: Path to the file to write
        data: Text data to write
    """
    # Ensure the directory exists
    ensure_directory_exists(os.path.dirname(file_path))
    
    with open(file_path, 'w', encoding=TEXT_ENCODING) as f:
        f.write(data)


# =============================================================================
# LOGGING SETUP
# =============================================================================

def setup_logger(name: str, log_file: Optional[str] = None) -> logging.Logger:
    """
    Set up and return a configured logger.
    
    Args:
        name: Name for the logger (usually __name__ of the module)
        log_file: Optional path to a log file. If None, logs to console only.
        
    Returns:
        Configured logger instance
    """
    # LEARN: Logging is essential for debugging and monitoring
    # LEARN: Instead of using print(), use logging which gives you:
    # LEARN: - Timestamps, log levels (DEBUG/INFO/WARNING/ERROR)
    # LEARN: - Easy filtering of messages by level
    # LEARN: - Output to both console and file simultaneously
    
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, LOG_LEVEL))
    
    # LEARN: Formatter defines how each log message looks
    formatter = logging.Formatter(LOG_FORMAT)
    
    # Console handler - prints to terminal
    # LEARN: StreamHandler() without arguments defaults to sys.stderr
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler - writes to log file
    if log_file:
        ensure_directory_exists(os.path.dirname(log_file))
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


# =============================================================================
# DATA VALIDATION
# =============================================================================

def is_valid_username(username: str) -> bool:
    """
    Validate a username for acceptable format.
    
    Args:
        username: Username to validate
        
    Returns:
        True if username is valid, False otherwise
    """
    # LEARN: Input validation is crucial for security
    # LEARN: Without it, attackers could send malformed data to crash the app
    # LEARN: or inject malicious content
    
    if not username:
        return False
    
    if len(username) < 3 or len(username) > 20:
        return False
    
    # Only allow alphanumeric characters and underscores
    # LEARN: This prevents injection attacks and ensures safe file names
    return username.replace('_', '').isalnum()


def sanitize_filename(filename: str) -> str:
    """
    Remove or replace unsafe characters from a filename.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename safe for use in file paths
    """
    # LEARN: Path traversal attack: using "../" to access files outside
    # LEARN: the intended directory. We must remove these characters.
    
    # Remove path separators and other dangerous characters
    unsafe_chars = ['/', '\\', '..', ':', '*', '?', '"', '<', '>', '|']
    result = filename
    
    for char in unsafe_chars:
        result = result.replace(char, '_')
    
    return result


# =============================================================================
# RANDOM DATA GENERATION
# =============================================================================

def generate_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.
    
    Args:
        length: Number of random bytes to generate
        
    Returns:
        Random bytes
    """
    # LEARN: os.urandom() uses the operating system's secure random generator
    # LEARN: This is suitable for cryptographic purposes (keys, nonces, IVs)
    # LEARN: NEVER use random.random() for security - it's predictable!
    
    return os.urandom(length)


def generate_nonce() -> bytes:
    """
    Generate a random nonce (number used once).
    
    A nonce is used to prevent replay attacks by ensuring each message
    is unique.
    
    Returns:
        Random nonce bytes
    """
    # LEARN: Nonce = Number used ONCE
    # LEARN: Each message includes a unique nonce. If an attacker replays
    # LEARN: the message, the server will see the same nonce twice and reject it.
    
    return generate_random_bytes(NONCE_SIZE)


# =============================================================================
# DISPLAY FORMATTING
# =============================================================================

def format_bytes_hex(data: bytes, max_length: int = 32) -> str:
    """
    Format bytes as a hexadecimal string for display.
    
    Args:
        data: Bytes to format
        max_length: Maximum number of bytes to show
        
    Returns:
        Hex string representation
    """
    # LEARN: Hexadecimal is useful for displaying binary data in logs
    # LEARN: Each byte becomes two hex characters (00-FF)
    
    hex_str = data[:max_length].hex()
    if len(data) > max_length:
        hex_str += f"... ({len(data)} bytes total)"
    return hex_str


def print_separator(char: str = "-", length: int = 50) -> None:
    """
    Print a visual separator line.
    
    Args:
        char: Character to repeat
        length: Number of times to repeat
    """
    print(char * length)
