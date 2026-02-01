"""
Crypto Package
==============
All cryptographic operations for SecureChat.

Modules:
    - aes: AES-256-GCM encryption (confidentiality at rest) [Charles]
    - rsa: RSA-2048 encryption and signatures (key exchange, non-repudiation) [Amir & 3]
    - kdf: PBKDF2 key derivation (private key protection) [Denise]
    - hmac_utils: HMAC-SHA256 (integrity in transit) [Denise]
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# AES-256-GCM (Confidentiality at Rest)
from crypto.aes import (
    generate_aes_key,
    aes_gcm_encrypt,
    aes_gcm_decrypt
)

# RSA-2048 (Key Exchange + Non-Repudiation)
from crypto.rsa import (
    generate_rsa_keypair,
    rsa_encrypt,
    rsa_decrypt,
    rsa_sign,
    rsa_verify
)

# PBKDF2 Key Derivation (Private Key Protection)
from crypto.kdf import (
    derive_key,
    encrypt_private_key,
    decrypt_private_key
)

# HMAC-SHA256 (Integrity in Transit)
from crypto.hmac_utils import (
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
