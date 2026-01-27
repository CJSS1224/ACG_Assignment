"""
Cryptographic Model - ST2504 Applied Cryptography

This model provides all cryptographic operations for SecureChat:
- AES-256-CTR Encryption/Decryption (Charles)
- HMAC-SHA256 Integrity (Amir)
- RSA Digital Signatures (Yong Cheng)
- RSA Key Management (Denise)

All cryptographic operations are implemented in Python using the 'cryptography' library.
"""

import os
import base64
import hmac as hmac_module
from typing import Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class CryptoModel:
    """
    Cryptographic model providing:
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
        """Convert bytes to Base64 string."""
        return base64.b64encode(data).decode('utf-8')
    
    def base64_to_bytes(self, data: str) -> bytes:
        """Convert Base64 string back to bytes."""
        return base64.b64decode(data.encode('utf-8'))
    
    def generate_random_bytes(self, length: int) -> bytes:
        """Generate cryptographically secure random bytes."""
        return os.urandom(length)
    
    # ==========================================================================
    # AES ENCRYPTION - Charles
    # ==========================================================================
    
    def generate_aes_key(self) -> bytes:
        """Generate a random AES-256 key."""
        return self.generate_random_bytes(self.AES_KEY_SIZE)
    
    def generate_nonce(self) -> bytes:
        """Generate a random nonce for AES-CTR mode."""
        return self.generate_random_bytes(self.AES_BLOCK_SIZE)
    
    def aes_encrypt(self, plaintext: str, key: bytes) -> Tuple[str, str]:
        """Encrypt a message using AES-256-CTR."""
        plaintext_bytes = plaintext.encode('utf-8')
        nonce = self.generate_nonce()
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CTR(nonce),
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
        
        return self.bytes_to_base64(ciphertext), self.bytes_to_base64(nonce)
    
    def aes_decrypt(self, ciphertext_b64: str, nonce_b64: str, key: bytes) -> str:
        """Decrypt a message using AES-256-CTR."""
        ciphertext = self.base64_to_bytes(ciphertext_b64)
        nonce = self.base64_to_bytes(nonce_b64)
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CTR(nonce),
            backend=default_backend()
        )
        
        decryptor = cipher.decryptor()
        plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext_bytes.decode('utf-8')
    
    # ==========================================================================
    # HMAC INTEGRITY - Amir
    # ==========================================================================
    
    def generate_hmac_key(self) -> bytes:
        """Generate a random HMAC key."""
        return self.generate_random_bytes(self.HMAC_KEY_SIZE)
    
    def generate_hmac(self, message: str, key: bytes) -> str:
        """Generate HMAC-SHA256 for message integrity."""
        h = HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(message.encode('utf-8'))
        hmac_bytes = h.finalize()
        return self.bytes_to_base64(hmac_bytes)
    
    def verify_hmac(self, message: str, hmac_b64: str, key: bytes) -> bool:
        """Verify HMAC-SHA256 for a message."""
        try:
            expected_hmac = self.generate_hmac(message, key)
            return hmac_module.compare_digest(expected_hmac, hmac_b64)
        except Exception:
            return False
    
    # ==========================================================================
    # RSA DIGITAL SIGNATURES - Yong Cheng
    # ==========================================================================
    
    def sign_message(self, message: str, private_key_pem: str) -> str:
        """Sign a message using RSA-PKCS1v15 with SHA-256."""
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        signature = private_key.sign(
            message.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        return self.bytes_to_base64(signature)
    
    def verify_signature(self, message: str, signature_b64: str, public_key_pem: str) -> bool:
        """Verify a message signature using RSA-PKCS1v15 with SHA-256."""
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            signature = self.base64_to_bytes(signature_b64)
            
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
    # RSA KEY MANAGEMENT - Denise
    # ==========================================================================
    
    def generate_rsa_keypair(self) -> Tuple[str, str]:
        """Generate an RSA-2048 key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.RSA_KEY_SIZE,
            backend=default_backend()
        )
        
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return private_key_pem, public_key_pem
    
    # FOR ENCRYPTED PRIVATE KEY ONLY

    def rsa_encrypt(self, data: bytes, public_key_pem: str) -> str:
        """Encrypt data using RSA-OAEP."""
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
        
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
        """Decrypt data using RSA-OAEP."""
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        ciphertext = self.base64_to_bytes(ciphertext_b64)
        
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
        """Encrypt a message with full security."""
        aes_key = self.generate_aes_key()
        ciphertext_b64, nonce_b64 = self.aes_encrypt(plaintext, aes_key)
        encrypted_key_recipient = self.rsa_encrypt(aes_key, recipient_public_key)
        encrypted_key_sender = self.rsa_encrypt(aes_key, sender_public_key)
        
        payload_to_sign = f"{ciphertext_b64}:{nonce_b64}"
        signature = self.sign_message(payload_to_sign, sender_private_key)
        
        hmac_key = self.generate_hmac_key()
        hmac_value = self.generate_hmac(payload_to_sign, hmac_key)
        
        return {
            'encrypted_payload': ciphertext_b64,
            'encrypted_key': encrypted_key_recipient,
            'encrypted_key_sender': encrypted_key_sender,
            'iv': nonce_b64,
            'signature': signature,
            'hmac': hmac_value
        }
    
    def decrypt_message(self, encrypted_data: dict, private_key: str,
                        sender_public_key: str = None) -> dict:
        """Decrypt a message and verify its signature."""
        try:
            aes_key = self.rsa_decrypt(encrypted_data['encrypted_key'], private_key)
        except Exception:
            if encrypted_data.get('encrypted_key_sender'):
                aes_key = self.rsa_decrypt(encrypted_data['encrypted_key_sender'], private_key)
            else:
                raise
        
        plaintext = self.aes_decrypt(
            encrypted_data['encrypted_payload'],
            encrypted_data['iv'],
            aes_key
        )
        
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
    
    # ==========================================================================
    # PRIVATE KEY ENCRYPTION FOR STORAGE - Denise
    # ==========================================================================
    
    def derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        """
        Derive an AES key from password using PBKDF2.
        This allows us to encrypt the private key with the user's password.
        """
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=salt,
            iterations=100000,  # High iteration count for security
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    def encrypt_private_key(self, private_key_pem: str, password: str) -> dict:
        """
        Encrypt a private key using a password-derived key.
        
        Returns:
            dict with encrypted_key, iv, and salt (all Base64 encoded)
        """
        # Generate random salt and IV
        salt = self.generate_random_bytes(16)
        iv = self.generate_nonce()
        
        # Derive AES key from password
        aes_key = self.derive_key_from_password(password, salt)
        
        # Encrypt the private key
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CTR(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted_key = encryptor.update(private_key_pem.encode('utf-8')) + encryptor.finalize()
        
        return {
            'encrypted_private_key': self.bytes_to_base64(encrypted_key),
            'iv': self.bytes_to_base64(iv),
            'salt': self.bytes_to_base64(salt)
        }
    
    def decrypt_private_key(self, encrypted_private_key: str, iv: str, 
                            salt: str, password: str) -> str:
        """
        Decrypt a private key using the password.
        
        Returns:
            Decrypted private key PEM string
        """
        # Decode from Base64
        encrypted_key_bytes = self.base64_to_bytes(encrypted_private_key)
        iv_bytes = self.base64_to_bytes(iv)
        salt_bytes = self.base64_to_bytes(salt)
        
        # Derive AES key from password
        aes_key = self.derive_key_from_password(password, salt_bytes)
        
        # Decrypt the private key
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CTR(iv_bytes),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        private_key_bytes = decryptor.update(encrypted_key_bytes) + decryptor.finalize()
        
        return private_key_bytes.decode('utf-8')
