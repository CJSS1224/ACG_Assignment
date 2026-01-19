"""
Cryptography Module

This module contains all cryptographic operations used in the secure
messaging application. It is divided into three sub-modules based on
the security property they provide:

Sub-modules:
    - encryption.py  (Member 3): AES-256 encryption for confidentiality
    - integrity.py   (Member 4): HMAC-SHA256 for integrity verification
    - signatures.py  (Member 5): RSA digital signatures for non-repudiation

Security Properties Achieved:
    - Confidentiality: Only authorized parties can read the message content
    - Integrity: Any tampering with the message is detected
    - Non-repudiation: Sender cannot deny having sent the message
"""


# Re-export commonly used functions for easier imports

from src.crypto.encryption import encrypt_message, decrypt_message
from src.crypto.integrity import generate_hmac, verify_hmac
from src.crypto.signatures import sign_message, verify_signature
