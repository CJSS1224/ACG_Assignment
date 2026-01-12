"""
Digital signature stubs.
Use cryptography.hazmat.primitives.asymmetric.rsa + padding + hashes in real code.
"""
from typing import Tuple

def sign_message(message: bytes, private_key) -> bytes:
    raise NotImplementedError

def verify_signature(message: bytes, signature: bytes, public_key) -> bool:
    raise NotImplementedError

def load_private_key(filepath: str, password: bytes = None):
    raise NotImplementedError

def load_public_key(filepath: str):
    raise NotImplementedError
