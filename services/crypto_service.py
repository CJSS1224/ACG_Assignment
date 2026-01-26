"""
Cryptographic Service - ST2504 Applied Cryptography

This module provides all cryptographic operations for SecureChat:
- AES-256-CTR Encryption/Decryption (Charles)
- HMAC-SHA256 Integrity (Amir)
- RSA Digital Signatures (Yong Cheng)
- RSA Key Management (Denise)

All cryptographic operations are implemented in Python using the 'cryptography' library.
"""

import os
import base64
import hmac as hmac_module
import hashlib
from typing import Tuple, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class CryptoService:
    """
    Unified cryptographic service providing:
    - AES encryption for message confidentiality
    - HMAC for message integrity
    - RSA signatures for non-repudiation
    - RSA key management for secure key exchange
    """
    
    # ==========================================================================
    # CONSTANTS
    # ==========================================================================
    
    AES_KEY_SIZE = 32      # 256 bits
    AES_BLOCK_SIZE = 16    # 128 bits (for nonce)
    RSA_KEY_SIZE = 2048    # bits
    HMAC_KEY_SIZE = 32     # 256 bits
    
    # ==========================================================================
    # UTILITY METHODS
    # ==========================================================================
    
    def bytes_to_base64(self, data: bytes) -> str:
        """Convert bytes to Base64 string for safe transmission/storage."""
        return base64.b64encode(data).decode('utf-8')
    
    def base64_to_bytes(self, data: str) -> bytes:
        """Convert Base64 string back to bytes."""
        return base64.b64decode(data.encode('utf-8'))
    
    def generate_random_bytes(self, length: int) -> bytes:
        """Generate cryptographically secure random bytes."""
        return os.urandom(length)
    
    # ==========================================================================
    # AES ENCRYPTION - Member 3
    # ==========================================================================
    
    def generate_aes_key(self) -> bytes:
        """
        Generate a random AES-256 key.
        
        Returns:
            32 bytes of cryptographically secure random data
        """
        return self.generate_random_bytes(self.AES_KEY_SIZE)
    
    def generate_nonce(self) -> bytes:
        """
        Generate a random nonce for AES-CTR mode.
        
        The nonce MUST be unique for each message with the same key.
        
        Returns:
            16 bytes of cryptographically secure random data
        """
        return self.generate_random_bytes(self.AES_BLOCK_SIZE)
    
    def aes_encrypt(self, plaintext: str, key: bytes) -> Tuple[str, str]:
        """
        Encrypt a message using AES-256-CTR.
        
        AES-CTR (Counter Mode):
        - Turns block cipher into stream cipher
        - No padding required
        - Parallelizable
        - Nonce must never be reused with same key
        
        Args:
            plaintext: Message to encrypt
            key: 32-byte AES key
            
        Returns:
            Tuple of (ciphertext_base64, nonce_base64)
        """
        # Convert plaintext to bytes
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Generate random nonce
        nonce = self.generate_nonce()
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.CTR(nonce),
            backend=default_backend()
        )
        
        # Encrypt
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
        
        return self.bytes_to_base64(ciphertext), self.bytes_to_base64(nonce)
    
    def aes_decrypt(self, ciphertext_b64: str, nonce_b64: str, key: bytes) -> str:
        """
        Decrypt a message using AES-256-CTR.
        
        Args:
            ciphertext_b64: Base64-encoded ciphertext
            nonce_b64: Base64-encoded nonce
            key: 32-byte AES key (same key used for encryption)
            
        Returns:
            Decrypted plaintext string
        """
        # Decode from Base64
        ciphertext = self.base64_to_bytes(ciphertext_b64)
        nonce = self.base64_to_bytes(nonce_b64)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.CTR(nonce),
            backend=default_backend()
        )
        
        # Decrypt
        decryptor = cipher.decryptor()
        plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext_bytes.decode('utf-8')
    
    # ==========================================================================
    # HMAC INTEGRITY - Member 4
    # ==========================================================================
    
    def generate_hmac_key(self) -> bytes:
        """
        Generate a random HMAC key.
        
        Returns:
            32 bytes of cryptographically secure random data
        """
        return self.generate_random_bytes(self.HMAC_KEY_SIZE)
    
    def generate_hmac(self, message: str, key: bytes) -> str:
        """
        Generate HMAC-SHA256 for message integrity.
        
        HMAC (Hash-based Message Authentication Code):
        - Verifies both integrity and authenticity
        - Requires shared secret key
        - Detects any modification to the message
        
        Args:
            message: Message to authenticate
            key: HMAC key (32 bytes recommended)
            
        Returns:
            Base64-encoded HMAC
        """
        h = HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(message.encode('utf-8'))
        hmac_bytes = h.finalize()
        return self.bytes_to_base64(hmac_bytes)
    
    def verify_hmac(self, message: str, hmac_b64: str, key: bytes) -> bool:
        """
        Verify HMAC-SHA256 for a message.
        
        Args:
            message: Original message
            hmac_b64: Base64-encoded HMAC to verify
            key: HMAC key (same key used for generation)
            
        Returns:
            True if HMAC is valid, False otherwise
        """
        try:
            expected_hmac = self.generate_hmac(message, key)
            # Use constant-time comparison to prevent timing attacks
            return hmac_module.compare_digest(expected_hmac, hmac_b64)
        except Exception:
            return False
    
    # ==========================================================================
    # RSA DIGITAL SIGNATURES - Member 5
    # ==========================================================================
    
    def sign_message(self, message: str, private_key_pem: str) -> str:
        """
        Sign a message using RSA-PKCS1v15 with SHA-256.
        
        Digital Signatures provide:
        - Non-repudiation: Sender cannot deny sending
        - Authentication: Proves message came from private key holder
        - Integrity: Any modification invalidates signature
        
        Args:
            message: Message to sign
            private_key_pem: Signer's private key in PEM format
            
        Returns:
            Base64-encoded signature
        """
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        # Sign the message
        signature = private_key.sign(
            message.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        return self.bytes_to_base64(signature)
    
    def verify_signature(self, message: str, signature_b64: str, public_key_pem: str) -> bool:
        """
        Verify a message signature using RSA-PKCS1v15 with SHA-256.
        
        Args:
            message: Original message
            signature_b64: Base64-encoded signature
            public_key_pem: Signer's public key in PEM format
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Load public key
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            # Decode signature
            signature = self.base64_to_bytes(signature_b64)
            
            # Verify
            public_key.verify(
                signature,
                message.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            print(f"[CRYPTO] Signature verification error: {e}")
            return False
    
    # ==========================================================================
    # RSA KEY MANAGEMENT - Member 6
    # ==========================================================================
    
    def generate_rsa_keypair(self) -> Tuple[str, str]:
        """
        Generate an RSA-2048 key pair.
        
        RSA Key Pair:
        - Private key: Keep secret, used for decryption and signing
        - Public key: Share freely, used for encryption and verification
        
        Returns:
            Tuple of (private_key_pem, public_key_pem)
        """
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.RSA_KEY_SIZE,
            backend=default_backend()
        )
        
        # Serialize private key to PEM
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        # Get public key and serialize to PEM
        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return private_key_pem, public_key_pem
    
    def rsa_encrypt(self, data: bytes, public_key_pem: str) -> str:
        """
        Encrypt data using RSA-OAEP.
        
        RSA-OAEP (Optimal Asymmetric Encryption Padding):
        - More secure than PKCS1v15 for encryption
        - Used for encrypting small data like AES keys
        
        Args:
            data: Data to encrypt (max ~190 bytes for RSA-2048)
            public_key_pem: Recipient's public key in PEM format
            
        Returns:
            Base64-encoded encrypted data
        """
        # Load public key
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
        
        # Encrypt
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return self.bytes_to_base64(ciphertext)
    
    def rsa_decrypt(self, ciphertext_b64: str, private_key_pem: str) -> bytes:
        """
        Decrypt data using RSA-OAEP.
        
        Args:
            ciphertext_b64: Base64-encoded encrypted data
            private_key_pem: Own private key in PEM format
            
        Returns:
            Decrypted data bytes
        """
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        # Decode ciphertext
        ciphertext = self.base64_to_bytes(ciphertext_b64)
        
        # Decrypt
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return plaintext
    
    # ==========================================================================
    # HIGH-LEVEL MESSAGE OPERATIONS
    # ==========================================================================
    
    def encrypt_message(self, plaintext: str, recipient_public_key: str, 
                        sender_private_key: str, sender_public_key: str) -> dict:
        """
        Encrypt a message with full security (confidentiality, integrity, non-repudiation).
        
        This implements hybrid encryption:
        1. Generate random AES key (for speed)
        2. Encrypt message with AES (Member 3)
        3. Encrypt AES key with recipient's RSA public key (Member 6)
        4. Encrypt AES key with sender's RSA public key (so sender can read own messages)
        5. Sign the ciphertext (Member 5)
        6. Generate HMAC for integrity (Member 4)
        
        Args:
            plaintext: Message to encrypt
            recipient_public_key: Recipient's RSA public key (PEM)
            sender_private_key: Sender's RSA private key (PEM) for signing
            sender_public_key: Sender's RSA public key (PEM) for self-decryption
            
        Returns:
            Dictionary with all encrypted components
        """
        # 1. Generate random AES key
        aes_key = self.generate_aes_key()
        
        # 2. Encrypt message with AES
        ciphertext_b64, nonce_b64 = self.aes_encrypt(plaintext, aes_key)
        
        # 3. Encrypt AES key for recipient
        encrypted_key_recipient = self.rsa_encrypt(aes_key, recipient_public_key)
        
        # 4. Encrypt AES key for sender (so they can read their own messages)
        encrypted_key_sender = self.rsa_encrypt(aes_key, sender_public_key)
        
        # 5. Sign the ciphertext (for non-repudiation)
        payload_to_sign = f"{ciphertext_b64}:{nonce_b64}"
        signature = self.sign_message(payload_to_sign, sender_private_key)
        
        # 6. Generate HMAC (for integrity)
        hmac_key = self.generate_hmac_key()
        hmac_value = self.generate_hmac(payload_to_sign, hmac_key)
        
        return {
            'encrypted_payload': ciphertext_b64,
            'encrypted_key': encrypted_key_recipient,
            'encrypted_key_sender': encrypted_key_sender,
            'iv': nonce_b64,  # Called 'iv' for compatibility, but it's a nonce for CTR
            'signature': signature,
            'hmac': hmac_value
        }
    
    def decrypt_message(self, encrypted_data: dict, private_key: str, 
                        sender_public_key: str = None) -> dict:
        """
        Decrypt a message and verify its signature.
        
        Args:
            encrypted_data: Dictionary with encrypted components
            private_key: Recipient's RSA private key (PEM)
            sender_public_key: Sender's RSA public key (PEM) for signature verification
            
        Returns:
            Dictionary with plaintext and signature verification status
        """
        # 1. Decrypt the AES key
        try:
            aes_key = self.rsa_decrypt(encrypted_data['encrypted_key'], private_key)
        except Exception:
            # Try sender's key (if reading own message)
            if encrypted_data.get('encrypted_key_sender'):
                aes_key = self.rsa_decrypt(encrypted_data['encrypted_key_sender'], private_key)
            else:
                raise
        
        # 2. Decrypt the message
        plaintext = self.aes_decrypt(
            encrypted_data['encrypted_payload'],
            encrypted_data['iv'],
            aes_key
        )
        
        # 3. Verify signature if sender's public key provided
        signature_valid = None
        if sender_public_key and encrypted_data.get('signature'):
            payload_to_verify = f"{encrypted_data['encrypted_payload']}:{encrypted_data['iv']}"
            signature_valid = self.verify_signature(
                payload_to_verify,
                encrypted_data['signature'],
                sender_public_key
            )
        
        return {
            'plaintext': plaintext,
            'signature_valid': signature_valid
        }
