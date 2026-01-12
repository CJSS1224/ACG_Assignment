"""
AES encryption/decryption stubs.
Implementations should use cryptography.hazmat.primitives.ciphers.aead or similar.
"""
from typing import Tuple
import os

def generate_aes_key(length: int = 32) -> bytes:
    return os.urandom(length)

def encrypt_message(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    # returns (nonce/ciphertext, tag_or_meta)
    raise NotImplementedError

def decrypt_message(ciphertext: bytes, key: bytes, meta: bytes) -> bytes:
    raise NotImplementedError
