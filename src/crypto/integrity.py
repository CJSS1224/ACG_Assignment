"""
Integrity Module - Member 4: [Name]

This module provides message integrity verification using HMAC-SHA256
and related hashing functions.

Security Property: INTEGRITY
- Detects if a message has been tampered with during transmission
- Ensures data has not been modified since it was created

Algorithm: HMAC-SHA256
- HMAC (Hash-based Message Authentication Code) combines a key with hashing
- SHA-256 is a secure hash function producing 256-bit digests
- Only someone with the secret key can create a valid HMAC

Additional Features:
- Replay attack prevention using timestamps and nonces
- Password hashing for secure storage

Dependencies:
    - cryptography library for HMAC operations
"""

import os
import time
import hmac as hmac_module
import hashlib
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend

from src.utils.constants import (
    HMAC_KEY_SIZE,
    NONCE_SIZE,
    MAX_MESSAGE_AGE,
    TEXT_ENCODING
)
from src.utils.helpers import (
    generate_random_bytes,
    bytes_to_base64,
    base64_to_bytes,
    string_to_bytes,
    get_timestamp,
    is_timestamp_valid
)


# =============================================================================
# HMAC KEY GENERATION
# =============================================================================

def generate_hmac_key() -> bytes:
    """
    Generate a random key for HMAC operations.
    
    The HMAC key should be kept secret and shared only with parties
    who need to verify message integrity.
    
    Returns:
        32 bytes of cryptographically secure random data
    """
    # LEARN: The HMAC key should be at least as long as the hash output
    # LEARN: For SHA-256, that's 256 bits (32 bytes)
    # LEARN: Shorter keys provide less security
    # LEARN: This key is different from the encryption key!
    
    return generate_random_bytes(HMAC_KEY_SIZE)


# =============================================================================
# HMAC GENERATION AND VERIFICATION
# =============================================================================

def generate_hmac(message: bytes, key: bytes) -> bytes:
    """
    Generate an HMAC for a message.
    
    The HMAC is a "tag" that proves:
    1. The message hasn't been modified
    2. It was created by someone with the secret key
    
    Args:
        message: The data to authenticate (bytes)
        key: HMAC secret key
        
    Returns:
        HMAC digest (32 bytes for SHA-256)
    """
    # LEARN: HMAC works differently from just hashing:
    # LEARN: Regular hash: digest = HASH(message)
    # LEARN: HMAC: digest = HASH((key XOR opad) || HASH((key XOR ipad) || message))
    # LEARN: This construction prevents "length extension attacks"
    # LEARN: that affect plain hashes
    
    # LEARN: Create an HMAC object with the specified key and hash algorithm
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    
    # LEARN: update() adds data to be hashed (can be called multiple times)
    h.update(message)
    
    # LEARN: finalize() computes and returns the final HMAC digest
    return h.finalize()


def generate_hmac_string(message: str, key: bytes) -> str:
    """
    Generate an HMAC for a string message, returning Base64.
    
    Convenience function that handles string encoding and returns
    a Base64 string suitable for transmission.
    
    Args:
        message: The string to authenticate
        key: HMAC secret key
        
    Returns:
        Base64-encoded HMAC
    """
    message_bytes = string_to_bytes(message)
    hmac_bytes = generate_hmac(message_bytes, key)
    return bytes_to_base64(hmac_bytes)


def verify_hmac(message: bytes, hmac_value: bytes, key: bytes) -> bool:
    """
    Verify that an HMAC is valid for a message.
    
    This proves the message hasn't been tampered with and was created
    by someone with the secret key.
    
    Args:
        message: The original message data
        hmac_value: The HMAC to verify
        key: HMAC secret key
        
    Returns:
        True if HMAC is valid, False if message was tampered with
    """
    # LEARN: We recompute the HMAC and compare it to the provided value
    # LEARN: If they match, the message is authentic and unmodified
    
    # LEARN: IMPORTANT: We use hmac.compare_digest() instead of ==
    # LEARN: Regular == comparison can leak timing information
    # LEARN: An attacker could measure response time to guess the HMAC byte by byte
    # LEARN: compare_digest() takes constant time regardless of where bytes differ
    
    expected_hmac = generate_hmac(message, key)
    
    # LEARN: Constant-time comparison prevents timing attacks
    return hmac_module.compare_digest(expected_hmac, hmac_value)


def verify_hmac_string(message: str, hmac_base64: str, key: bytes) -> bool:
    """
    Verify an HMAC for a string message.
    
    Convenience function that handles Base64 decoding.
    
    Args:
        message: The original string message
        hmac_base64: Base64-encoded HMAC
        key: HMAC secret key
        
    Returns:
        True if HMAC is valid, False otherwise
    """
    message_bytes = string_to_bytes(message)
    hmac_bytes = base64_to_bytes(hmac_base64)
    return verify_hmac(message_bytes, hmac_bytes, key)


# =============================================================================
# HASHING (WITHOUT KEY)
# =============================================================================

def hash_sha256(data: bytes) -> bytes:
    """
    Compute the SHA-256 hash of data.
    
    Unlike HMAC, this doesn't require a key. It's used for:
    - Creating unique identifiers for data
    - Password hashing (with salt)
    - Checking data integrity (when authenticity isn't needed)
    
    Args:
        data: Data to hash
        
    Returns:
        32-byte SHA-256 digest
    """
    # LEARN: SHA-256 is a one-way function:
    # LEARN: - Given data, easy to compute hash
    # LEARN: - Given hash, practically impossible to find original data
    # LEARN: - Small change in input = completely different hash (avalanche effect)
    
    # LEARN: hashlib is Python's built-in hash library
    return hashlib.sha256(data).digest()


def hash_sha256_string(data: str) -> str:
    """
    Compute SHA-256 hash of a string, returning hex digest.
    
    Args:
        data: String to hash
        
    Returns:
        64-character hexadecimal hash string
    """
    # LEARN: .hexdigest() returns a hex string instead of bytes
    # LEARN: Hex is often used because it's human-readable
    
    return hashlib.sha256(string_to_bytes(data)).hexdigest()


def hash_message(message: str) -> str:
    """
    Create a hash fingerprint of a message.
    
    Useful for creating message IDs or checking if messages are identical.
    
    Args:
        message: Message to hash
        
    Returns:
        Base64-encoded hash (shorter than hex)
    """
    hash_bytes = hash_sha256(string_to_bytes(message))
    return bytes_to_base64(hash_bytes)


# =============================================================================
# NONCE GENERATION AND TRACKING
# =============================================================================

# LEARN: This set tracks nonces we've seen to prevent replay attacks
# LEARN: In production, this should be persistent (database) not in-memory
_seen_nonces = set()


def generate_nonce() -> bytes:
    """
    Generate a random nonce (number used once).
    
    A nonce ensures each message is unique, preventing replay attacks
    where an attacker re-sends a captured message.
    
    Returns:
        16 bytes of random data
    """
    # LEARN: Nonce = "Number used ONCE"
    # LEARN: Each message includes a unique nonce
    # LEARN: Server tracks seen nonces and rejects duplicates
    # LEARN: This prevents attackers from replaying old messages
    
    return generate_random_bytes(NONCE_SIZE)


def generate_nonce_string() -> str:
    """
    Generate a nonce and return as Base64 string.
    
    Returns:
        Base64-encoded nonce
    """
    return bytes_to_base64(generate_nonce())


def check_and_record_nonce(nonce: str) -> bool:
    """
    Check if a nonce has been seen before and record it.
    
    This prevents replay attacks by rejecting messages with
    previously-used nonces.
    
    Args:
        nonce: Base64-encoded nonce string
        
    Returns:
        True if nonce is new (message is fresh)
        False if nonce was seen before (possible replay attack!)
    """
    # LEARN: Replay attack defense:
    # LEARN: 1. Every message includes a unique nonce
    # LEARN: 2. Server records all nonces it has processed
    # LEARN: 3. If the same nonce appears twice, reject the message
    # LEARN: 4. This means captured messages can't be re-sent
    
    global _seen_nonces
    
    if nonce in _seen_nonces:
        # LEARN: We've seen this nonce before - possible attack!
        return False
    
    # Record the nonce
    _seen_nonces.add(nonce)
    
    # LEARN: In production, we'd also need to clean old nonces
    # LEARN: to prevent the set from growing forever
    
    return True


def clear_nonce_cache() -> None:
    """
    Clear the nonce cache. Used for testing.
    
    In production, you'd implement nonce expiration instead.
    """
    global _seen_nonces
    _seen_nonces = set()


# =============================================================================
# TIMESTAMP VALIDATION
# =============================================================================

def create_timestamp() -> float:
    """
    Create a Unix timestamp for the current time.
    
    Returns:
        Current time as seconds since Unix epoch
    """
    return get_timestamp()


def verify_timestamp(timestamp: float, max_age: float = MAX_MESSAGE_AGE) -> Tuple[bool, str]:
    """
    Verify that a timestamp is recent enough.
    
    This prevents replay attacks by rejecting old messages.
    
    Args:
        timestamp: Unix timestamp to verify
        max_age: Maximum allowed age in seconds
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    # LEARN: Timestamp checking has two purposes:
    # LEARN: 1. Reject very old messages (captured and replayed later)
    # LEARN: 2. Reject messages from the future (clock manipulation attack)
    
    if is_timestamp_valid(timestamp, max_age):
        return True, "Timestamp is valid"
    
    current_time = get_timestamp()
    age = current_time - timestamp
    
    if age < -60:  # More than 1 minute in future
        return False, "Timestamp is in the future - possible clock manipulation"
    
    return False, f"Message is too old ({age:.0f} seconds > {max_age} seconds max)"


# =============================================================================
# COMBINED INTEGRITY CHECK
# =============================================================================

def create_integrity_data(message: str, hmac_key: bytes) -> dict:
    """
    Create all integrity verification data for a message.
    
    This generates everything needed to verify the message later:
    - HMAC for integrity
    - Nonce for replay prevention
    - Timestamp for freshness
    
    Args:
        message: The message to protect
        hmac_key: Key for HMAC generation
        
    Returns:
        Dictionary with 'hmac', 'nonce', 'timestamp' fields
    """
    # LEARN: This function bundles all integrity mechanisms together
    # LEARN: When sending a message, include this data
    # LEARN: When receiving, verify all of it before processing
    
    nonce = generate_nonce_string()
    timestamp = create_timestamp()
    
    # LEARN: We include nonce and timestamp in the HMAC calculation
    # LEARN: This prevents attackers from modifying these values
    integrity_string = f"{message}|{nonce}|{timestamp}"
    hmac_value = generate_hmac_string(integrity_string, hmac_key)
    
    return {
        'hmac': hmac_value,
        'nonce': nonce,
        'timestamp': timestamp
    }


def verify_integrity_data(
    message: str,
    integrity_data: dict,
    hmac_key: bytes
) -> Tuple[bool, str]:
    """
    Verify all integrity data for a received message.
    
    Checks:
    1. HMAC is valid (message not tampered)
    2. Nonce is fresh (not a replay)
    3. Timestamp is recent (not an old message)
    
    Args:
        message: The received message
        integrity_data: Dictionary with 'hmac', 'nonce', 'timestamp'
        hmac_key: Key for HMAC verification
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    # LEARN: Defense in depth: multiple checks for multiple attack vectors
    # LEARN: All checks must pass for the message to be accepted
    
    # Extract values
    hmac_value = integrity_data.get('hmac', '')
    nonce = integrity_data.get('nonce', '')
    timestamp = integrity_data.get('timestamp', 0)
    
    # Check timestamp first (cheapest operation)
    timestamp_valid, timestamp_error = verify_timestamp(timestamp)
    if not timestamp_valid:
        return False, f"Timestamp check failed: {timestamp_error}"
    
    # Check nonce (prevents replay)
    if not check_and_record_nonce(nonce):
        return False, "Nonce already used - possible replay attack!"
    
    # Check HMAC (proves integrity)
    integrity_string = f"{message}|{nonce}|{timestamp}"
    if not verify_hmac_string(integrity_string, hmac_value, hmac_key):
        return False, "HMAC verification failed - message may be tampered!"
    
    return True, "Integrity verified"


# =============================================================================
# PASSWORD HASHING (FOR USER AUTHENTICATION)
# =============================================================================

def hash_password(password: str, salt: bytes = None) -> Tuple[str, str]:
    """
    Hash a password for secure storage.
    
    Never store passwords in plain text! Always hash them.
    
    Args:
        password: The password to hash
        salt: Optional salt (generated if not provided)
        
    Returns:
        Tuple of (hashed_password_base64, salt_base64)
    """
    # LEARN: Password hashing is different from message hashing:
    # LEARN: 1. We use a random salt to prevent rainbow table attacks
    # LEARN: 2. We use a slow hash to prevent brute force attacks
    # LEARN: 3. Each password has a unique salt stored with the hash
    
    # LEARN: A "salt" is random data added to the password before hashing
    # LEARN: This means identical passwords produce different hashes
    # LEARN: Attackers can't pre-compute hashes of common passwords
    
    if salt is None:
        salt = generate_random_bytes(16)
    
    # LEARN: Combine password and salt, then hash
    # LEARN: In production, use a dedicated password hash like Argon2 or bcrypt
    salted_password = salt + string_to_bytes(password)
    password_hash = hash_sha256(salted_password)
    
    return bytes_to_base64(password_hash), bytes_to_base64(salt)


def verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
    """
    Verify a password against a stored hash.
    
    Args:
        password: The password attempt to verify
        stored_hash: The stored hash (Base64)
        stored_salt: The stored salt (Base64)
        
    Returns:
        True if password matches, False otherwise
    """
    # LEARN: Verification process:
    # LEARN: 1. Get the salt that was used when storing
    # LEARN: 2. Hash the provided password with that salt
    # LEARN: 3. Compare with stored hash
    
    salt = base64_to_bytes(stored_salt)
    
    # Hash the provided password with the same salt
    salted_password = salt + string_to_bytes(password)
    computed_hash = hash_sha256(salted_password)
    
    # Compare with stored hash
    stored_hash_bytes = base64_to_bytes(stored_hash)
    
    # LEARN: Use constant-time comparison to prevent timing attacks
    return hmac_module.compare_digest(computed_hash, stored_hash_bytes)
