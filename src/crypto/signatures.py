"""
Signatures Module - Member 5: [Name]

This module provides digital signature functionality using RSA for
ensuring non-repudiation of messages.

Security Property: NON-REPUDIATION
- Proves who sent a message (authentication)
- Sender cannot deny having sent the message
- Provides legal evidence of origin

Algorithm: RSA with PKCS#1 v1.5 padding
- Private key signs the message (only sender can do this)
- Public key verifies the signature (anyone can do this)
- SHA-256 is used as the hash function

How it works:
1. Sender hashes the message
2. Sender encrypts the hash with their PRIVATE key (this is the signature)
3. Recipient decrypts the signature with sender's PUBLIC key
4. Recipient compares decrypted hash with their own hash of the message
5. If they match, signature is valid

Dependencies:
    - cryptography library for RSA operations
"""

from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from src.utils.helpers import (
    bytes_to_base64,
    base64_to_bytes,
    string_to_bytes,
    bytes_to_string
)


# =============================================================================
# DIGITAL SIGNATURE CREATION
# =============================================================================

def sign_message(message: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Create a digital signature for a message.
    
    The signature proves:
    1. The message was created by the owner of the private key
    2. The message has not been modified since signing
    
    Only the private key holder can create valid signatures.
    
    Args:
        message: The data to sign (bytes)
        private_key: Signer's RSA private key
        
    Returns:
        Digital signature (bytes)
    """
    # LEARN: Digital signature algorithm (simplified):
    # LEARN: 1. Compute hash of the message: H = SHA256(message)
    # LEARN: 2. "Encrypt" hash with private key: signature = H^d mod n
    # LEARN:    (where d is the private exponent, n is the modulus)
    # LEARN: 3. The result is the signature
    
    # LEARN: Why does this work?
    # LEARN: - Only the private key holder can create the signature
    # LEARN: - Anyone with the public key can verify it
    # LEARN: - If the message changes, the hash changes, signature becomes invalid
    
    # LEARN: PKCS1v15 is the padding scheme used for RSA signatures
    # LEARN: It adds structure to prevent certain mathematical attacks
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    return signature


def sign_message_string(message: str, private_key: rsa.RSAPrivateKey) -> str:
    """
    Sign a string message and return Base64-encoded signature.
    
    Convenience function for working with strings.
    
    Args:
        message: String message to sign
        private_key: Signer's RSA private key
        
    Returns:
        Base64-encoded signature
    """
    message_bytes = string_to_bytes(message)
    signature_bytes = sign_message(message_bytes, private_key)
    return bytes_to_base64(signature_bytes)


# =============================================================================
# DIGITAL SIGNATURE VERIFICATION
# =============================================================================

def verify_signature(
    message: bytes,
    signature: bytes,
    public_key: rsa.RSAPublicKey
) -> bool:
    """
    Verify a digital signature.
    
    This proves:
    1. The message came from the owner of the corresponding private key
    2. The message hasn't been modified since it was signed
    
    Anyone with the public key can verify signatures.
    
    Args:
        message: The original message data
        signature: The signature to verify
        public_key: Signer's RSA public key
        
    Returns:
        True if signature is valid, False otherwise
    """
    # LEARN: Verification algorithm:
    # LEARN: 1. "Decrypt" signature with public key: H' = signature^e mod n
    # LEARN:    (where e is the public exponent)
    # LEARN: 2. Compute hash of received message: H = SHA256(message)
    # LEARN: 3. Compare H' with H
    # LEARN: 4. If they match, signature is valid
    
    # LEARN: Why non-repudiation?
    # LEARN: - Only someone with the private key could create this signature
    # LEARN: - The private key owner cannot claim someone else signed it
    # LEARN: - This provides legal proof of origin
    
    try:
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
        
    except InvalidSignature:
        # LEARN: InvalidSignature exception means:
        # LEARN: - Message was tampered with, OR
        # LEARN: - Wrong public key (different sender), OR
        # LEARN: - Signature is corrupted
        return False


def verify_signature_string(
    message: str,
    signature_base64: str,
    public_key: rsa.RSAPublicKey
) -> bool:
    """
    Verify a signature on a string message.
    
    Convenience function that handles Base64 decoding.
    
    Args:
        message: The original string message
        signature_base64: Base64-encoded signature
        public_key: Signer's RSA public key
        
    Returns:
        True if signature is valid, False otherwise
    """
    message_bytes = string_to_bytes(message)
    signature_bytes = base64_to_bytes(signature_base64)
    return verify_signature(message_bytes, signature_bytes, public_key)


# =============================================================================
# SIGN WITH TIMESTAMP (ENHANCED NON-REPUDIATION)
# =============================================================================

def sign_with_timestamp(
    message: str,
    private_key: rsa.RSAPrivateKey,
    timestamp: float
) -> Tuple[str, str]:
    """
    Sign a message along with a timestamp.
    
    Including the timestamp in the signature proves WHEN the message
    was signed, not just WHO signed it.
    
    Args:
        message: Message to sign
        private_key: Signer's RSA private key
        timestamp: Unix timestamp to include
        
    Returns:
        Tuple of (signature_base64, signed_data)
        signed_data is the message + timestamp that was actually signed
    """
    # LEARN: Timestamped signatures are important for:
    # LEARN: - Legal documents (prove when a contract was signed)
    # LEARN: - Message ordering (prove message A was signed before message B)
    # LEARN: - Audit trails (know exactly when something happened)
    
    # LEARN: We concatenate message and timestamp, then sign the whole thing
    # LEARN: This binds the timestamp to the message - can't change one without
    # LEARN: invalidating the signature
    signed_data = f"{message}|{timestamp}"
    signature = sign_message_string(signed_data, private_key)
    
    return signature, signed_data


def verify_with_timestamp(
    message: str,
    timestamp: float,
    signature_base64: str,
    public_key: rsa.RSAPublicKey
) -> bool:
    """
    Verify a timestamped signature.
    
    Args:
        message: The original message
        timestamp: The timestamp that was signed with the message
        signature_base64: Base64-encoded signature
        public_key: Signer's RSA public key
        
    Returns:
        True if signature is valid for this message AND timestamp
    """
    # Reconstruct what was signed
    signed_data = f"{message}|{timestamp}"
    return verify_signature_string(signed_data, signature_base64, public_key)


# =============================================================================
# SIGN MESSAGE FOR STORAGE (AT-REST NON-REPUDIATION)
# =============================================================================

def create_signed_package(
    message: str,
    sender_name: str,
    private_key: rsa.RSAPrivateKey
) -> dict:
    """
    Create a complete signed package for storage.
    
    This format includes everything needed to verify the signature later:
    - The original message
    - Sender identification
    - Timestamp of signing
    - The signature itself
    
    This is suitable for at-rest storage where we need to preserve
    non-repudiation evidence.
    
    Args:
        message: Message to sign
        sender_name: Identifier of the signer
        private_key: Signer's RSA private key
        
    Returns:
        Dictionary with all components needed for verification
    """
    # LEARN: "At-rest" non-repudiation means we can prove who sent what
    # LEARN: even after the message is stored on disk
    # LEARN: This is different from "in-transit" where we verify immediately
    
    from src.utils.helpers import get_timestamp
    
    timestamp = get_timestamp()
    
    # Create the data to sign (includes all context)
    # LEARN: Including sender_name prevents someone from claiming
    # LEARN: a different sender created the message
    data_to_sign = f"{sender_name}|{message}|{timestamp}"
    
    signature = sign_message_string(data_to_sign, private_key)
    
    return {
        'message': message,
        'sender': sender_name,
        'timestamp': timestamp,
        'signature': signature,
        'algorithm': 'RSA-PKCS1v15-SHA256'
    }


def verify_signed_package(
    package: dict,
    public_key: rsa.RSAPublicKey
) -> Tuple[bool, str]:
    """
    Verify a signed package from storage.
    
    Args:
        package: Dictionary from create_signed_package()
        public_key: Claimed sender's RSA public key
        
    Returns:
        Tuple of (is_valid, error_or_success_message)
    """
    try:
        # Extract components
        message = package.get('message', '')
        sender = package.get('sender', '')
        timestamp = package.get('timestamp', 0)
        signature = package.get('signature', '')
        
        # Reconstruct what was signed
        data_to_sign = f"{sender}|{message}|{timestamp}"
        
        # Verify
        if verify_signature_string(data_to_sign, signature, public_key):
            return True, f"Signature valid. Message from {sender} at {timestamp}"
        else:
            return False, "Signature verification failed"
            
    except Exception as e:
        return False, f"Verification error: {str(e)}"


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_signature_info() -> dict:
    """
    Get information about the signature algorithm in use.
    
    Useful for documentation and audit purposes.
    
    Returns:
        Dictionary with algorithm details
    """
    return {
        'algorithm': 'RSA',
        'padding': 'PKCS#1 v1.5',
        'hash': 'SHA-256',
        'key_size': '2048 bits (recommended minimum)',
        'signature_size': '256 bytes (for 2048-bit key)'
    }


def compare_signatures(sig1: str, sig2: str) -> bool:
    """
    Compare two signatures for equality.
    
    Uses constant-time comparison to prevent timing attacks.
    
    Args:
        sig1: First signature (Base64)
        sig2: Second signature (Base64)
        
    Returns:
        True if signatures are identical
    """
    import hmac
    
    try:
        sig1_bytes = base64_to_bytes(sig1)
        sig2_bytes = base64_to_bytes(sig2)
        return hmac.compare_digest(sig1_bytes, sig2_bytes)
    except Exception:
        return False


# =============================================================================
# BATCH SIGNING (FOR MULTIPLE MESSAGES)
# =============================================================================

def sign_multiple_messages(
    messages: list,
    private_key: rsa.RSAPrivateKey
) -> list:
    """
    Sign multiple messages at once.
    
    Each message gets its own signature.
    
    Args:
        messages: List of string messages
        private_key: Signer's RSA private key
        
    Returns:
        List of tuples (message, signature_base64)
    """
    # LEARN: Signing each message separately provides flexibility
    # LEARN: Each message can be verified independently
    # LEARN: If one signature fails, others are still valid
    
    results = []
    for message in messages:
        signature = sign_message_string(message, private_key)
        results.append((message, signature))
    
    return results


def verify_multiple_messages(
    message_signature_pairs: list,
    public_key: rsa.RSAPublicKey
) -> list:
    """
    Verify multiple message/signature pairs.
    
    Args:
        message_signature_pairs: List of (message, signature) tuples
        public_key: Signer's RSA public key
        
    Returns:
        List of tuples (message, is_valid)
    """
    results = []
    for message, signature in message_signature_pairs:
        is_valid = verify_signature_string(message, signature, public_key)
        results.append((message, is_valid))
    
    return results
