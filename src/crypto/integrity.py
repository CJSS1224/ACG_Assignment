"""
HMAC and hashing stubs.
"""
from typing import Tuple
import os
import hashlib

def hash_message(message: bytes) -> bytes:
    return hashlib.sha256(message).digest()

def generate_hmac(message: bytes, key: bytes) -> bytes:
    raise NotImplementedError

def verify_hmac(message: bytes, hmac_value: bytes, key: bytes) -> bool:
    raise NotImplementedError

def generate_nonce() -> bytes:
    return os.urandom(16)

def verify_timestamp(timestamp: float, max_age: int) -> bool:
    import time
    return (time.time() - timestamp) <= max_age
