"""
Crypto Service

Wraps the existing cryptographic modules to provide easy-to-use
functions for the web application.
"""

import os
import sys

# Add src to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.crypto.encryption import (
    generate_aes_key,
    encrypt_message,
    decrypt_message
)
from src.crypto.integrity import (
    generate_hmac_string,
    verify_hmac_string
)
from src.crypto.signatures import (
    sign_message_string,
    verify_signature_string
)
from src.pki.key_management import (
    generate_rsa_keypair,
    public_key_to_pem_string,
    pem_string_to_public_key,
    private_key_to_pem_string,
    pem_string_to_private_key,
    encrypt_session_key,
    decrypt_session_key
)
from src.utils.helpers import (
    bytes_to_base64,
    base64_to_bytes
)


def generate_user_keypair():
    """
    Generate a new RSA key pair for a user.
    
    Returns:
        Tuple of (private_key_pem, public_key_pem) as strings
    """
    private_key, public_key = generate_rsa_keypair()
    private_pem = private_key_to_pem_string(private_key)
    public_pem = public_key_to_pem_string(public_key)
    return private_pem, public_pem


def encrypt_message_for_recipient(plaintext, recipient_public_key_pem, sender_private_key_pem, hmac_key=None):
    """
    Encrypt a message for a recipient using hybrid encryption.
    
    This implements the full security scheme:
    - Confidentiality: AES-256 encryption
    - Integrity: HMAC-SHA256
    - Non-repudiation: RSA digital signature
    
    Args:
        plaintext: Message text to encrypt
        recipient_public_key_pem: Recipient's public key (PEM string)
        sender_private_key_pem: Sender's private key (PEM string)
        hmac_key: Optional HMAC key (generates one if not provided)
        
    Returns:
        Dict containing encrypted payload, encrypted key, IV, signature, and HMAC
    """
    # Generate a random AES key for this message
    aes_key = generate_aes_key()
    
    # Encrypt the message with AES
    ciphertext_b64, iv_b64 = encrypt_message(plaintext, aes_key)
    
    # Encrypt the AES key with recipient's public key
    recipient_public_key = pem_string_to_public_key(recipient_public_key_pem)
    encrypted_aes_key = encrypt_session_key(aes_key, recipient_public_key)
    encrypted_key_b64 = bytes_to_base64(encrypted_aes_key)
    
    # Create payload for signing (ciphertext + iv)
    payload_to_sign = f"{ciphertext_b64}:{iv_b64}"
    
    # Sign with sender's private key (non-repudiation)
    sender_private_key = pem_string_to_private_key(sender_private_key_pem)
    signature = sign_message_string(payload_to_sign, sender_private_key)
    
    # Generate HMAC for integrity
    if hmac_key is None:
        from src.crypto.integrity import generate_hmac_key
        hmac_key = generate_hmac_key()
    hmac_value = generate_hmac_string(payload_to_sign, hmac_key)
    
    return {
        'encrypted_payload': ciphertext_b64,
        'encrypted_key': encrypted_key_b64,
        'iv': iv_b64,
        'signature': signature,
        'hmac': hmac_value
    }


def decrypt_message_from_sender(encrypted_data, recipient_private_key_pem, sender_public_key_pem=None):
    """
    Decrypt a message from a sender.
    
    Args:
        encrypted_data: Dict containing encrypted payload, key, IV, signature
        recipient_private_key_pem: Recipient's private key (PEM string)
        sender_public_key_pem: Sender's public key for signature verification (optional)
        
    Returns:
        Dict with plaintext and verification status
    """
    # Decrypt the AES key with recipient's private key
    recipient_private_key = pem_string_to_private_key(recipient_private_key_pem)
    encrypted_aes_key = base64_to_bytes(encrypted_data['encrypted_key'])
    aes_key = decrypt_session_key(encrypted_aes_key, recipient_private_key)
    
    # Decrypt the message
    plaintext = decrypt_message(
        encrypted_data['encrypted_payload'],
        encrypted_data['iv'],
        aes_key
    )
    
    # Verify signature if public key provided
    signature_valid = None
    if sender_public_key_pem and encrypted_data.get('signature'):
        sender_public_key = pem_string_to_public_key(sender_public_key_pem)
        payload_to_verify = f"{encrypted_data['encrypted_payload']}:{encrypted_data['iv']}"
        signature_valid = verify_signature_string(
            payload_to_verify,
            encrypted_data['signature'],
            sender_public_key
        )
    
    return {
        'plaintext': plaintext,
        'signature_valid': signature_valid
    }


def verify_message_integrity(encrypted_data, hmac_key):
    """
    Verify message integrity using HMAC.
    
    Args:
        encrypted_data: Dict containing encrypted payload, IV, and HMAC
        hmac_key: HMAC key
        
    Returns:
        True if integrity check passes
    """
    payload_to_verify = f"{encrypted_data['encrypted_payload']}:{encrypted_data['iv']}"
    return verify_hmac_string(payload_to_verify, encrypted_data['hmac'], hmac_key)


def verify_message_signature(encrypted_data, sender_public_key_pem):
    """
    Verify message signature for non-repudiation.
    
    Args:
        encrypted_data: Dict containing encrypted payload, IV, and signature
        sender_public_key_pem: Sender's public key (PEM string)
        
    Returns:
        True if signature is valid
    """
    sender_public_key = pem_string_to_public_key(sender_public_key_pem)
    payload_to_verify = f"{encrypted_data['encrypted_payload']}:{encrypted_data['iv']}"
    return verify_signature_string(
        payload_to_verify,
        encrypted_data['signature'],
        sender_public_key
    )
