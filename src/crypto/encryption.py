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

# LEARN: We import from cryptography.hazmat which provides low-level
# LEARN: cryptographic primitives. "hazmat" stands for "hazardous materials"
# LEARN: because using these incorrectly can lead to security vulnerabilities
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
    # LEARN: AES key must be exactly 16, 24, or 32 bytes for AES-128/192/256
    # LEARN: We use 32 bytes for AES-256, the strongest variant
    # LEARN: The key MUST be generated using a secure random source (os.urandom)
    # LEARN: NEVER use predictable values like passwords directly as keys!
    
    return generate_random_bytes(AES_KEY_SIZE)


def generate_iv() -> bytes:
    """
    Generate a random Initialization Vector (IV) for AES-CBC.
    
    The IV ensures that encrypting the same plaintext twice produces
    different ciphertext each time.
    
    Returns:
        16 bytes (128 bits) of cryptographically secure random data
    """
    # LEARN: The IV (Initialization Vector) is critical for CBC mode security
    # LEARN: It must be:
    # LEARN:   - Random and unpredictable for each encryption operation
    # LEARN:   - The same size as the AES block size (16 bytes)
    # LEARN:   - Transmitted with the ciphertext (it's not secret)
    # LEARN: Without a random IV, identical plaintexts produce identical ciphertexts
    # LEARN: which leaks information about the data!
    
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
    # LEARN: PKCS7 padding works like this:
    # LEARN: If 3 bytes needed: add 0x03 0x03 0x03
    # LEARN: If 5 bytes needed: add 0x05 0x05 0x05 0x05 0x05
    # LEARN: If data is already aligned, add a full block of 0x10 (16)
    # LEARN: This allows unambiguous removal during decryption
    
    # LEARN: AES_BLOCK_SIZE * 8 converts bytes to bits (16 * 8 = 128)
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
    # LEARN: Invalid padding usually means:
    # LEARN: 1. Data was tampered with
    # LEARN: 2. Wrong key was used for decryption
    # LEARN: 3. Data corruption occurred
    # LEARN: This is why we also use HMAC for integrity - catch tampering early!
    
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
    # LEARN: Cipher Block Chaining (CBC) mode explained:
    # LEARN: 1. XOR the first plaintext block with the IV
    # LEARN: 2. Encrypt the XOR result with AES
    # LEARN: 3. Use that ciphertext block as the "IV" for the next block
    # LEARN: 4. Repeat for all blocks
    # LEARN: This chains blocks together - changing one plaintext byte
    # LEARN: affects ALL subsequent ciphertext blocks
    
    # LEARN: Create a Cipher object configured for AES-CBC
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    
    # LEARN: The encryptor object performs the actual encryption
    encryptor = cipher.encryptor()
    
    # LEARN: update() processes the data, finalize() completes the operation
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
    # LEARN: Decryption is the reverse process:
    # LEARN: 1. Decrypt each ciphertext block with AES
    # LEARN: 2. XOR with the previous ciphertext block (or IV for first block)
    # LEARN: 3. Result is the original plaintext block
    
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
    # LEARN: This function combines all steps needed for secure encryption:
    # LEARN: 1. Encoding: Convert Python string to bytes (UTF-8)
    # LEARN: 2. Padding: Make data length multiple of 16 bytes
    # LEARN: 3. IV Generation: Create random 16 bytes for this message
    # LEARN: 4. Encryption: AES-256-CBC transform
    # LEARN: 5. Encoding: Convert binary to Base64 for safe transmission
    
    # Convert string to bytes
    plaintext_bytes = string_to_bytes(plaintext)
    
    # Pad the data
    padded_data = pad_data(plaintext_bytes)
    
    # Generate random IV
    iv = generate_iv()
    
    # Encrypt
    ciphertext = aes_encrypt_raw(padded_data, key, iv)
    
    # LEARN: Convert to Base64 for safe transmission/storage
    # LEARN: Binary data can have null bytes and control characters
    # LEARN: that break text-based protocols like JSON or HTTP
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
    # LEARN: Steps in reverse order:
    # LEARN: 1. Decode Base64 back to binary
    # LEARN: 2. Decrypt using AES-256-CBC
    # LEARN: 3. Remove PKCS7 padding
    # LEARN: 4. Decode UTF-8 bytes back to string
    
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
    # LEARN: Bundling the IV with ciphertext is a common pattern
    # LEARN: The IV doesn't need to be secret, just unique
    # LEARN: Prepending makes it easy to extract during decryption
    
    plaintext_bytes = string_to_bytes(plaintext)
    padded_data = pad_data(plaintext_bytes)
    iv = generate_iv()
    
    ciphertext = aes_encrypt_raw(padded_data, key, iv)
    
    # Prepend IV to ciphertext
    # LEARN: IV is always 16 bytes, so we know where to split during decryption
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
    # LEARN: File encryption works the same as message encryption
    # LEARN: but reads/writes to files instead of strings
    
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
    # LEARN: "At-rest" encryption protects data that's stored on disk
    # LEARN: Even if an attacker gets access to the storage, they can't
    # LEARN: read the data without the encryption key
    
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
