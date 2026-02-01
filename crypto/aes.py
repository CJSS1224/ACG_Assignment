"""
AES-256-GCM Encryption Module
=============================
Implemented by: Charles (AES Encryption Specialist)

Provides CONFIDENTIALITY AT REST

AES-GCM provides both encryption AND authentication in one operation.
The authentication tag ensures data hasn't been tampered with.

Functions:
    - aes_gcm_encrypt: Encrypt plaintext, returns (ciphertext, nonce, tag)
    - aes_gcm_decrypt: Decrypt ciphertext, verifies tag, returns plaintext
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Constants
AES_KEY_SIZE = 32  # 256 bits
NONCE_SIZE = 12    # 96 bits (recommended for GCM)


def generate_aes_key() -> bytes:
    """Generate a random 256-bit AES key. [Charles]"""
    return os.urandom(AES_KEY_SIZE)


def aes_gcm_encrypt(plaintext: str, key: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt plaintext using AES-256-GCM. [Charles]
    
    Args:
        plaintext: The message to encrypt
        key: 32-byte AES key
        
    Returns:
        tuple: (ciphertext, nonce, tag)
        - ciphertext: The encrypted message
        - nonce: Random 12-byte value (must be unique per encryption)
        - tag: 16-byte authentication tag (appended to ciphertext by AESGCM)
        
    Note:
        AESGCM.encrypt() returns ciphertext + tag concatenated.
        We split them for clarity in storage.
    """
    # Generate random nonce (MUST be unique for each encryption with same key)
    nonce = os.urandom(NONCE_SIZE)
    
    # Create cipher and encrypt
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    
    # AESGCM appends 16-byte tag to ciphertext
    # Split them for clearer storage
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    
    return ciphertext, nonce, tag


def aes_gcm_decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> str:
    """
    Decrypt ciphertext using AES-256-GCM. [Charles]
    
    Args:
        ciphertext: The encrypted message
        key: 32-byte AES key
        nonce: The nonce used during encryption
        tag: The authentication tag
        
    Returns:
        str: The decrypted plaintext
        
    Raises:
        cryptography.exceptions.InvalidTag: If tag verification fails
            (meaning data was tampered with or wrong key)
    """
    # Reconstruct ciphertext + tag format expected by AESGCM
    ciphertext_with_tag = ciphertext + tag
    
    # Create cipher and decrypt (also verifies tag)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    
    return plaintext.decode('utf-8')
