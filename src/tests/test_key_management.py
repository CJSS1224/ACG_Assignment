import pytest
from src.pki import key_management

def test_key_management_stubs():
    with pytest.raises(NotImplementedError):
        key_management.generate_rsa_keypair()
