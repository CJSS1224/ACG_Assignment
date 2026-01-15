"""
ST2504 Applied Cryptography - Assignment 2
Secure Messaging Application

This package contains all source code for the secure messaging application
that demonstrates cryptographic principles including:
- Confidentiality (AES-256 encryption)
- Integrity (HMAC-SHA256)
- Non-repudiation (RSA digital signatures)

Package Structure:
    - server/   : Server application module
    - client/   : Client application module
    - crypto/   : Cryptographic functions (encryption, integrity, signatures)
    - pki/      : Public Key Infrastructure and key management
    - utils/    : Shared utilities, constants, and protocol definitions
    - tests/    : Unit tests for all modules
"""

# LEARN: This file makes the 'src' folder a Python package.
# LEARN: When Python sees __init__.py in a folder, it treats that folder
# LEARN: as a package that can be imported. Without this file, you cannot
# LEARN: do "from src import something" or "from src.crypto import encryption"

__version__ = "1.0.0"
__author__ = "ST2504 Assignment 2 Team"
