"""
HMAC Module
===========
Implemented by: Denise (HMAC & Key Derivation Specialist)

Provides INTEGRITY IN TRANSIT using HMAC-SHA256.

HMAC (Hash-based Message Authentication Code) ensures that:
    - Messages are not tampered with during transmission
    - Messages come from someone who knows the secret

Each user session gets a unique secret key, preventing:
    - Replay attacks across sessions
    - One user impersonating another

Functions:
    - generate_session_secret: Create a new session HMAC key
    - generate_hmac: Create HMAC for outgoing data
    - verify_hmac: Verify HMAC on incoming data
"""

import os
import hmac
import hashlib
import json


# Constants
HMAC_KEY_SIZE = 32  # 256 bits


def generate_session_secret() -> bytes:
    """
    Generate a random session secret for HMAC operations. [Denise]
    
    Called once per login session. The secret is:
        - Stored on server (in session/memory)
        - Sent to client (over HTTPS)
        - Used for all HMAC operations during that session
    
    Returns:
        bytes: 32-byte random secret
    """
    return os.urandom(HMAC_KEY_SIZE)


def generate_hmac(data: dict, secret: bytes) -> str:
    """
    Generate HMAC-SHA256 for data being sent. [Denise]
    
    The data is serialized to JSON with sorted keys for consistency.
    
    Args:
        data: Dictionary to authenticate
        secret: Session HMAC secret (32 bytes)
        
    Returns:
        str: Hex-encoded HMAC
    """
    # Serialize data consistently (sorted keys, no spaces)
    data_str = json.dumps(data, sort_keys=True, separators=(',', ':'))
    
    # Generate HMAC
    h = hmac.new(secret, data_str.encode('utf-8'), hashlib.sha256)
    
    return h.hexdigest()


def verify_hmac(data: dict, received_hmac: str, secret: bytes) -> bool:
    """
    Verify HMAC-SHA256 of received data. [Denise]
    
    Uses constant-time comparison to prevent timing attacks.
    
    Args:
        data: Received dictionary (without the HMAC field)
        received_hmac: HMAC received with the data
        secret: Session HMAC secret (32 bytes)
        
    Returns:
        bool: True if HMAC is valid, False if tampered
    """
    expected_hmac = generate_hmac(data, secret)
    
    # Constant-time comparison prevents timing attacks
    return hmac.compare_digest(expected_hmac, received_hmac)
