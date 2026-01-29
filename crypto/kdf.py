"""
Key Derivation Module
=====================
Provides password-based key derivation using PBKDF2-SHA256.

Used to:
    - Derive encryption key from user's password
    - Encrypt/decrypt the user's RSA private key

The derived key is used with AES-GCM to protect the private key at rest.

Functions:
    - derive_key: Derive a 256-bit key from password + salt
    - encrypt_private_key: Encrypt RSA private key with password
    - decrypt_private_key: Decrypt RSA private key with password
"""

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .aes import aes_gcm_encrypt, aes_gcm_decrypt


# Constants
SALT_SIZE = 16           # 128 bits
PBKDF2_ITERATIONS = 100000  # OWASP recommended minimum
DERIVED_KEY_SIZE = 32    # 256 bits for AES-256


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit encryption key from a password.
    
    Uses PBKDF2 with SHA-256 and 100,000 iterations.
    
    Args:
        password: User's password
        salt: Random 16-byte salt (must be stored with encrypted data)
        
    Returns:
        bytes: 32-byte derived key suitable for AES-256
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=DERIVED_KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS
    )
    
    return kdf.derive(password.encode('utf-8'))


def encrypt_private_key(private_key_pem: str, password: str) -> dict:
    """
    Encrypt an RSA private key using the user's password.
    
    Process:
        1. Generate random salt
        2. Derive AES key from password + salt using PBKDF2
        3. Encrypt private key with AES-256-GCM
    
    Args:
        private_key_pem: RSA private key in PEM format
        password: User's password
        
    Returns:
        dict: {
            'encrypted_private_key': bytes,
            'nonce': bytes,
            'tag': bytes,
            'salt': bytes
        }
    """
    # Generate random salt for key derivation
    salt = os.urandom(SALT_SIZE)
    
    # Derive AES key from password
    aes_key = derive_key(password, salt)
    
    # Encrypt the private key
    ciphertext, nonce, tag = aes_gcm_encrypt(private_key_pem, aes_key)
    
    return {
        'encrypted_private_key': ciphertext,
        'nonce': nonce,
        'tag': tag,
        'salt': salt
    }


def decrypt_private_key(encrypted_data: dict, password: str) -> str:
    """
    Decrypt an RSA private key using the user's password.
    
    Args:
        encrypted_data: Dict with 'encrypted_private_key', 'nonce', 'tag', 'salt'
        password: User's password
        
    Returns:
        str: RSA private key in PEM format
        
    Raises:
        cryptography.exceptions.InvalidTag: If password is wrong
    """
    # Derive AES key from password
    aes_key = derive_key(password, encrypted_data['salt'])
    
    # Decrypt the private key
    private_key_pem = aes_gcm_decrypt(
        encrypted_data['encrypted_private_key'],
        aes_key,
        encrypted_data['nonce'],
        encrypted_data['tag']
    )
    
    return private_key_pem
