"""
PKI and key management stubs.
Do not store private keys in repo for production.
"""
def generate_rsa_keypair(key_size: int = 2048):
    raise NotImplementedError

def save_private_key(key, filepath: str, password: bytes = None):
    raise NotImplementedError

def save_public_key(key, filepath: str):
    raise NotImplementedError

def load_private_key(filepath: str, password: bytes = None):
    raise NotImplementedError

def load_public_key(filepath: str):
    raise NotImplementedError

def generate_certificate(subject, issuer_key, issuer_cert, days: int = 365):
    raise NotImplementedError
