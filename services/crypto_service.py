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
        return base64.b64encode(data).decode('utf-8')
    
    def base64_to_bytes(self, data: str) -> bytes:
        return base64.b64decode(data.encode('utf-8'))
    
    def generate_random_bytes(self, length: int) -> bytes:
        return os.urandom(length)
    
    # ==========================================================================
    # AES ENCRYPTION - Member 3
    # ==========================================================================
    
    def generate_aes_key(self) -> bytes:
        return self.generate_random_bytes(self.AES_KEY_SIZE)
    
    def generate_nonce(self) -> bytes:
        return self.generate_random_bytes(self.AES_BLOCK_SIZE)
    
    def aes_encrypt(self, plaintext: str, key: bytes) -> Tuple[str, str]:
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
    # HMAC INTEGRITY - Member 4
    # ==========================================================================
    
    def generate_hmac_key(self) -> bytes:
        return self.generate_random_bytes(self.HMAC_KEY_SIZE)
    
    def generate_hmac(self, message: str, key: bytes) -> str:
        h = HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(message.encode('utf-8'))
        hmac_bytes = h.finalize()
        return self.bytes_to_base64(hmac_bytes)
    
    def verify_hmac(self, message: str, hmac_b64: str, key: bytes) -> bool:
        try:
            expected_hmac = self.generate_hmac(message, key)
            return hmac_module.compare_digest(expected_hmac, hmac_b64)
        except Exception:
            return False
    
    # ==========================================================================
    # RSA DIGITAL SIGNATURES - Member 5
    # ==========================================================================
    
    def sign_message(self, message: str, private_key_pem: str) -> str:
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
    # RSA KEY MANAGEMENT - Member 6
    # ==========================================================================
    
    def generate_rsa_keypair(self) -> Tuple[str, str]:
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
    
    def rsa_encrypt(self, data: bytes, public_key_pem: str) -> str:
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
            'iv': nonce_b64,  # Called 'iv' for compatibility, but it's a nonce for CTR
            'signature': signature,
            'hmac': hmac_value
        }
    
    def decrypt_message(self, encrypted_data: dict, private_key: str, 
                        sender_public_key: str = None) -> dict:
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