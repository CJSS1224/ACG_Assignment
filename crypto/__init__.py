"""
Crypto Package
==============
All cryptographic operations for SecureChat.

Modules:
    - aes: AES-256-GCM encryption (confidentiality at rest)
    - rsa: RSA-2048 encryption and signatures (key exchange, non-repudiation)
    - kdf: PBKDF2 key derivation (private key protection)
    - hmac_utils: HMAC-SHA256 (integrity in transit)
"""

# AES-256-GCM (Confidentiality at Rest)
from .aes import (
    generate_aes_key,
    aes_gcm_encrypt,
    aes_gcm_decrypt
)

# RSA-2048 (Key Exchange + Non-Repudiation)
from .rsa import (
    generate_rsa_keypair,
    rsa_encrypt,
    rsa_decrypt,
    rsa_sign,
    rsa_verify
)

# PBKDF2 Key Derivation (Private Key Protection)
from .kdf import (
    derive_key,
    encrypt_private_key,
    decrypt_private_key
)

# HMAC-SHA256 (Integrity in Transit)
from .hmac_utils import (
    generate_session_secret,
    generate_hmac,
    verify_hmac
)

__all__ = [
    # AES
    'generate_aes_key',
    'aes_gcm_encrypt',
    'aes_gcm_decrypt',
    # RSA
    'generate_rsa_keypair',
    'rsa_encrypt',
    'rsa_decrypt',
    'rsa_sign',
    'rsa_verify',
    # KDF
    'derive_key',
    'encrypt_private_key',
    'decrypt_private_key',
    # HMAC
    'generate_session_secret',
    'generate_hmac',
    'verify_hmac',
]
