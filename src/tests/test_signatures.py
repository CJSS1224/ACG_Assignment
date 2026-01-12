import pytest
from src.crypto import signatures

def test_signature_stubs():
    with pytest.raises(NotImplementedError):
        signatures.sign_message(b"m", None)
