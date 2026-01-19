"""
Encryption Module - Member 3: [Name]

This module provides AES-256 encryption and decryption functionality
for protecting message confidentiality.

Security Property: CONFIDENTIALITY
- Only authorized parties with the correct key can read message content
- Even if messages are intercepted, they appear as random bytes

Algorithm: AES-256-CBC
- AES (Advanced Encryption Standard) is a symmetric block cipher
- 256-bit key provides strong security
- CBC (Cipher Block Chaining) mode links blocks together for better security

Dependencies:
    - cryptography library for AES operations
"""

import os
from typing import Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

from src.utils.constants import AES_KEY_SIZE, AES_BLOCK_SIZE
from src.utils.helpers import (
    generate_random_bytes,
    bytes_to_base64,
    base64_to_bytes,
    string_to_bytes,
    bytes_to_string
)


# =============================================================================
# AES KEY GENERATION
# =============================================================================

def generate_aes_key() -> bytes:
    """
    Generate a random AES-256 encryption key.
    
    The key should be kept secret and shared only with authorized parties.
    
    Returns:
        32 bytes (256 bits) of cryptographically secure random data
    """
    
    return generate_random_bytes(AES_KEY_SIZE)


def generate_iv() -> bytes:
    """
    Generate a random Initialization Vector (IV) for AES-CBC.
    
    The IV ensures that encrypting the same plaintext twice produces
    different ciphertext each time.
    
    Returns:
        16 bytes (128 bits) of cryptographically secure random data
    """
    
    return generate_random_bytes(AES_BLOCK_SIZE)


# =============================================================================
# PADDING OPERATIONS
# =============================================================================

def pad_data(data: bytes) -> bytes:
    """
    Apply PKCS7 padding to data to make it a multiple of block size.
    
    AES operates on fixed 16-byte blocks. If data isn't exactly divisible
    by 16, we must pad it.
    
    Args:
        data: Data to pad
        
    Returns:
        Padded data
    """
    
    padder = sym_padding.PKCS7(AES_BLOCK_SIZE * 8).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    return padded_data


def unpad_data(padded_data: bytes) -> bytes:
    """
    Remove PKCS7 padding from decrypted data.
    
    Args:
        padded_data: Data with padding
        
    Returns:
        Original data without padding
        
    Raises:
        ValueError: If padding is invalid (possible tampering detected)
    """
    
    unpadder = sym_padding.PKCS7(AES_BLOCK_SIZE * 8).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data


# =============================================================================
# LOW-LEVEL ENCRYPTION / DECRYPTION
# =============================================================================

def aes_encrypt_raw(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Encrypt raw bytes using AES-256-CBC.
    
    This is the low-level encryption function. For most uses, prefer
    encrypt_message() which handles encoding and Base64.
    
    Args:
        plaintext: Data to encrypt (must already be padded)
        key: 32-byte AES key
        iv: 16-byte initialization vector
        
    Returns:
        Encrypted ciphertext
    """
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    
    encryptor = cipher.encryptor()
    
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    return ciphertext


def aes_decrypt_raw(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt raw bytes using AES-256-CBC.
    
    This is the low-level decryption function. For most uses, prefer
    decrypt_message() which handles encoding and Base64.
    
    Args:
        ciphertext: Encrypted data
        key: 32-byte AES key (must be same key used for encryption)
        iv: 16-byte initialization vector (must be same IV used for encryption)
        
    Returns:
        Decrypted plaintext (still padded)
    """
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext


# =============================================================================
# HIGH-LEVEL MESSAGE ENCRYPTION / DECRYPTION
# =============================================================================

def encrypt_message(plaintext: str, key: bytes) -> Tuple[str, str]:
    """
    Encrypt a message string and return Base64-encoded ciphertext and IV.
    
    This is the main function for encrypting messages. It:
    1. Converts string to bytes
    2. Pads the data
    3. Generates a random IV
    4. Encrypts with AES-256-CBC
    5. Returns Base64-encoded results (safe for transmission)
    
    Args:
        plaintext: Message to encrypt (string)
        key: AES-256 key (32 bytes)
        
    Returns:
        Tuple of (ciphertext_base64, iv_base64)
        
    Example:
        >>> key = generate_aes_key()
        >>> ct, iv = encrypt_message("Hello World", key)
        >>> # ct and iv are Base64 strings safe for JSON/network
    """
    
    # Convert string to bytes
    plaintext_bytes = string_to_bytes(plaintext)
    
    # Pad the data
    padded_data = pad_data(plaintext_bytes)
    
    # Generate random IV
    iv = generate_iv()
    
    # Encrypt
    ciphertext = aes_encrypt_raw(padded_data, key, iv)
    
    ciphertext_base64 = bytes_to_base64(ciphertext)
    iv_base64 = bytes_to_base64(iv)
    
    return ciphertext_base64, iv_base64


def decrypt_message(ciphertext_base64: str, iv_base64: str, key: bytes) -> str:
    """
    Decrypt a Base64-encoded ciphertext back to the original message.
    
    This reverses encrypt_message():
    1. Decodes Base64 to bytes
    2. Decrypts with AES-256-CBC
    3. Removes padding
    4. Converts bytes back to string
    
    Args:
        ciphertext_base64: Base64-encoded ciphertext
        iv_base64: Base64-encoded IV
        key: AES-256 key (must be same key used for encryption)
        
    Returns:
        Original plaintext message
        
    Raises:
        ValueError: If decryption fails (wrong key, corrupted data)
    """
    
    # Decode from Base64
    ciphertext = base64_to_bytes(ciphertext_base64)
    iv = base64_to_bytes(iv_base64)
    
    # Decrypt
    padded_plaintext = aes_decrypt_raw(ciphertext, key, iv)
    
    # Remove padding
    plaintext_bytes = unpad_data(padded_plaintext)
    
    # Convert back to string
    plaintext = bytes_to_string(plaintext_bytes)
    
    return plaintext


# =============================================================================
# ENCRYPTION WITH BUNDLED IV
# =============================================================================

def encrypt_message_bundled(plaintext: str, key: bytes) -> str:
    """
    Encrypt a message and bundle the IV with the ciphertext.
    
    The IV is prepended to the ciphertext, making transmission simpler
    (only one value to send instead of two).
    
    Format: base64(IV + ciphertext)
    
    Args:
        plaintext: Message to encrypt
        key: AES-256 key
        
    Returns:
        Base64-encoded string containing IV + ciphertext
    """
    
    plaintext_bytes = string_to_bytes(plaintext)
    padded_data = pad_data(plaintext_bytes)
    iv = generate_iv()
    
    ciphertext = aes_encrypt_raw(padded_data, key, iv)
    
    # Prepend IV to ciphertext
    bundled = iv + ciphertext
    
    return bytes_to_base64(bundled)


def decrypt_message_bundled(bundled_base64: str, key: bytes) -> str:
    """
    Decrypt a message where IV is bundled with ciphertext.
    
    Args:
        bundled_base64: Base64-encoded IV + ciphertext
        key: AES-256 key
        
    Returns:
        Original plaintext message
    """
    # Decode from Base64
    bundled = base64_to_bytes(bundled_base64)
    
    # Extract IV (first 16 bytes) and ciphertext (rest)
    iv = bundled[:AES_BLOCK_SIZE]
    ciphertext = bundled[AES_BLOCK_SIZE:]
    
    # Decrypt
    padded_plaintext = aes_decrypt_raw(ciphertext, key, iv)
    plaintext_bytes = unpad_data(padded_plaintext)
    
    return bytes_to_string(plaintext_bytes)


# =============================================================================
# FILE ENCRYPTION (BONUS FEATURE)
# =============================================================================

def encrypt_file(input_path: str, output_path: str, key: bytes) -> str:
    """
    Encrypt a file and save to a new location.
    
    The IV is stored at the beginning of the encrypted file.
    
    Args:
        input_path: Path to the file to encrypt
        output_path: Path to save the encrypted file
        key: AES-256 key
        
    Returns:
        IV as Base64 string (also stored in file)
    """
    
    # Read the file
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    
    # Pad and encrypt
    padded_data = pad_data(plaintext)
    iv = generate_iv()
    ciphertext = aes_encrypt_raw(padded_data, key, iv)
    
    # Write IV + ciphertext to output file
    with open(output_path, 'wb') as f:
        f.write(iv)
        f.write(ciphertext)
    
    return bytes_to_base64(iv)


def decrypt_file(input_path: str, output_path: str, key: bytes) -> None:
    """
    Decrypt a file and save to a new location.
    
    Expects the IV to be stored at the beginning of the encrypted file.
    
    Args:
        input_path: Path to the encrypted file
        output_path: Path to save the decrypted file
        key: AES-256 key
    """
    # Read the encrypted file
    with open(input_path, 'rb') as f:
        data = f.read()
    
    # Extract IV and ciphertext
    iv = data[:AES_BLOCK_SIZE]
    ciphertext = data[AES_BLOCK_SIZE:]
    
    # Decrypt and unpad
    padded_plaintext = aes_decrypt_raw(ciphertext, key, iv)
    plaintext = unpad_data(padded_plaintext)
    
    # Write to output file
    with open(output_path, 'wb') as f:
        f.write(plaintext)


# =============================================================================
# ENCRYPTION FOR STORAGE (AT-REST)
# =============================================================================

def encrypt_for_storage(plaintext: str, key: bytes) -> dict:
    """
    Encrypt a message for secure storage (at-rest encryption).
    
    Returns a dictionary with all components needed to decrypt later.
    This format is suitable for storing in a database or JSON file.
    
    Args:
        plaintext: Message to encrypt
        key: AES-256 key
        
    Returns:
        Dictionary with 'ciphertext', 'iv', and 'algorithm' fields
    """
    
    ciphertext_b64, iv_b64 = encrypt_message(plaintext, key)
    
    return {
        'ciphertext': ciphertext_b64,
        'iv': iv_b64,
        'algorithm': 'AES-256-CBC'  # Document what was used
    }


def decrypt_from_storage(encrypted_data: dict, key: bytes) -> str:
    """
    Decrypt a message that was encrypted for storage.
    
    Args:
        encrypted_data: Dictionary from encrypt_for_storage()
        key: AES-256 key
        
    Returns:
        Original plaintext message
    """
    return decrypt_message(
        encrypted_data['ciphertext'],
        encrypted_data['iv'],
        key
    )
