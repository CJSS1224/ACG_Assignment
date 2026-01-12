import pytest
from src.crypto.encryption import generate_aes_key

def test_generate_aes_key_length():
    k = generate_aes_key()
    assert isinstance(k, bytes)
    assert len(k) == 32
