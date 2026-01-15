"""
Tests Module

This module contains unit tests for all cryptographic and utility functions.
Tests ensure that each component works correctly in isolation before
integration.

Test Files:
    - test_encryption.py      : Tests for AES encryption/decryption
    - test_integrity.py       : Tests for HMAC generation/verification
    - test_signatures.py      : Tests for digital signature operations
    - test_key_management.py  : Tests for PKI functions

Running Tests:
    From the project root directory:
    $ python -m pytest src/tests/
    
    Or run individual test files:
    $ python -m pytest src/tests/test_encryption.py
"""

# LEARN: Unit testing is crucial for cryptographic code. A small bug in
# LEARN: encryption could make your entire system insecure. Tests verify
# LEARN: that encryption followed by decryption returns the original data,
# LEARN: that invalid signatures are rejected, etc.
