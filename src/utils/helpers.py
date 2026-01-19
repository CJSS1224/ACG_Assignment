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
    
    return base64.b64decode(data.encode(TEXT_ENCODING))


def string_to_bytes(data: str) -> bytes:
    """
    Convert a string to bytes using UTF-8 encoding.
    
    Args:
        data: String to convert
        
    Returns:
        UTF-8 encoded bytes
    """
    
    return data.encode(TEXT_ENCODING)


def bytes_to_string(data: bytes) -> str:
    """
    Convert bytes to a string using UTF-8 decoding.
    
    Args:
        data: Bytes to convert
        
    Returns:
        UTF-8 decoded string
    """
    
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
    
    return time.time()


def get_timestamp_string() -> str:
    """
    Get the current timestamp as a formatted string.
    
    Returns:
        Timestamp in ISO 8601 format (YYYY-MM-DD HH:MM:SS)
    """
    
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
    
    current_time = get_timestamp()
    age = current_time - timestamp
    
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
    
    with open(file_path, 'rb') as f:
        return f.read()


def write_file_bytes(file_path: str, data: bytes) -> None:
    """
    Write binary data to a file.
    
    Args:
        file_path: Path to the file to write
        data: Binary data to write
    """
    
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
    
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, LOG_LEVEL))
    
    formatter = logging.Formatter(LOG_FORMAT)
    
    # Console handler - prints to terminal
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
    
    if not username:
        return False
    
    if len(username) < 3 or len(username) > 20:
        return False
    
    # Only allow alphanumeric characters and underscores
    return username.replace('_', '').isalnum()


def sanitize_filename(filename: str) -> str:
    """
    Remove or replace unsafe characters from a filename.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename safe for use in file paths
    """
    
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
    
    return os.urandom(length)


def generate_nonce() -> bytes:
    """
    Generate a random nonce (number used once).
    
    A nonce is used to prevent replay attacks by ensuring each message
    is unique.
    
    Returns:
        Random nonce bytes
    """
    
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
