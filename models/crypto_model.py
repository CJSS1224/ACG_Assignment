"""
Cryptographic Model - ST2504 Applied Cryptography
==================================================

All cryptographic operations for SecureChat:
- AES-256-CTR Encryption/Decryption (Charles)
- HMAC-SHA256 Integrity (Amir)
- RSA Digital Signatures (Yong Cheng)
- RSA Key Management (Denise)
"""

import os
import base64
import hmac as hmac_module
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class CryptoModel:
    """All cryptographic operations for SecureChat."""
    
    AES_KEY_SIZE = 32   # 256 bits
    RSA_KEY_SIZE = 2048
    
    # ==================== UTILITIES ====================
    
    def to_base64(self, data: bytes) -> str:
        return base64.b64encode(data).decode('utf-8')
    
    def from_base64(self, data: str) -> bytes:
        return base64.b64decode(data.encode('utf-8'))
    
    # ==================== AES-256-CTR ENCRYPTION (Charles) ====================
    
    def aes_encrypt(self, plaintext: str, key: bytes) -> tuple:
        """Encrypt message using AES-256-CTR."""
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        return self.to_base64(ciphertext), self.to_base64(nonce)
    
    def aes_decrypt(self, ciphertext_b64: str, nonce_b64: str, key: bytes) -> str:
        """Decrypt message using AES-256-CTR."""
        ciphertext = self.from_base64(ciphertext_b64)
        nonce = self.from_base64(nonce_b64)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode('utf-8')
    
    # ==================== HMAC-SHA256 INTEGRITY (Amir) ====================
    
    def generate_hmac(self, message: str, key: bytes) -> str:
        """Generate HMAC-SHA256 for message integrity."""
        h = HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(message.encode('utf-8'))
        return self.to_base64(h.finalize())
    
    def verify_hmac(self, message: str, hmac_b64: str, key: bytes) -> bool:
        """Verify HMAC-SHA256."""
        expected = self.generate_hmac(message, key)
        return hmac_module.compare_digest(expected, hmac_b64)
    
    # ==================== RSA DIGITAL SIGNATURES (Yong Cheng) ====================
    
    def sign_message(self, message: str, private_key_pem: str) -> str:
        """Sign message using RSA-PKCS1v15 with SHA-256."""
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'), password=None, backend=default_backend()
        )
        signature = private_key.sign(
            message.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return self.to_base64(signature)
    
    def verify_signature(self, message: str, signature_b64: str, public_key_pem: str) -> bool:
        """Verify RSA signature."""
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'), backend=default_backend()
            )
            public_key.verify(
                self.from_base64(signature_b64),
                message.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False
    
    # ==================== RSA KEY MANAGEMENT (Denise) ====================
    
    def generate_rsa_keypair(self) -> tuple:
        """Generate RSA-2048 key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.RSA_KEY_SIZE,
            backend=default_backend()
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return private_pem, public_pem
    
    def rsa_encrypt(self, data: bytes, public_key_pem: str) -> str:
        """Encrypt data using RSA-OAEP."""
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'), backend=default_backend()
        )
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return self.to_base64(ciphertext)
    
    def rsa_decrypt(self, ciphertext_b64: str, private_key_pem: str) -> bytes:
        """Decrypt data using RSA-OAEP."""
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'), password=None, backend=default_backend()
        )
        return private_key.decrypt(
            self.from_base64(ciphertext_b64),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    # ==================== PRIVATE KEY ENCRYPTION (Denise) ====================
    
    def encrypt_private_key(self, private_key_pem: str, password: str) -> dict:
        """Encrypt private key using password-derived key (PBKDF2 + AES)."""
        salt = os.urandom(16)
        iv = os.urandom(16)
        
        # Derive key from password using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        aes_key = kdf.derive(password.encode('utf-8'))
        
        # Encrypt private key
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(private_key_pem.encode('utf-8')) + encryptor.finalize()
        
        return {
            'encrypted_private_key': self.to_base64(encrypted),
            'iv': self.to_base64(iv),
            'salt': self.to_base64(salt)
        }
    
    def decrypt_private_key(self, encrypted_b64: str, iv_b64: str, salt_b64: str, password: str) -> str:
        """Decrypt private key using password."""
        salt = self.from_base64(salt_b64)
        iv = self.from_base64(iv_b64)
        encrypted = self.from_base64(encrypted_b64)
        
        # Derive key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        aes_key = kdf.derive(password.encode('utf-8'))
        
        # Decrypt private key
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(encrypted) + decryptor.finalize()).decode('utf-8')
    
    # ==================== HIGH-LEVEL MESSAGE OPERATIONS ====================
    
    def encrypt_message(self, plaintext: str, recipient_public_key: str,
                        sender_private_key: str, sender_public_key: str) -> dict:
        """
        Encrypt a message with full security:
        - AES-256-CTR for confidentiality (Charles)
        - RSA-OAEP for key exchange (Denise)
        - RSA signature for non-repudiation (Yong Cheng)
        - HMAC-SHA256 for integrity (Amir)
        """
        # Generate random AES key
        aes_key = os.urandom(self.AES_KEY_SIZE)
        
        # Encrypt message with AES-256-CTR
        ciphertext_b64, nonce_b64 = self.aes_encrypt(plaintext, aes_key)
        
        # Encrypt AES key for recipient and sender (RSA-OAEP)
        encrypted_key_recipient = self.rsa_encrypt(aes_key, recipient_public_key)
        encrypted_key_sender = self.rsa_encrypt(aes_key, sender_public_key)
        
        # Sign the ciphertext (non-repudiation)
        payload = f"{ciphertext_b64}:{nonce_b64}"
        signature = self.sign_message(payload, sender_private_key)
        
        # Generate HMAC for integrity
        hmac_key = os.urandom(32)
        hmac_value = self.generate_hmac(payload, hmac_key)
        
        return {
            'encrypted_payload': ciphertext_b64,
            'encrypted_key': encrypted_key_recipient,
            'encrypted_key_sender': encrypted_key_sender,
            'iv': nonce_b64,
            'signature': signature,
            'hmac': hmac_value
        }
    
    def decrypt_message(self, encrypted_data: dict, private_key: str, sender_public_key: str = None) -> dict:
        """Decrypt a message and verify signature."""
        # Decrypt AES key
        try:
            aes_key = self.rsa_decrypt(encrypted_data['encrypted_key'], private_key)
        except:
            aes_key = self.rsa_decrypt(encrypted_data['encrypted_key_sender'], private_key)
        
        # Decrypt message
        plaintext = self.aes_decrypt(
            encrypted_data['encrypted_payload'],
            encrypted_data['iv'],
            aes_key
        )
        
        # Verify signature
        signature_valid = None
        if sender_public_key and encrypted_data.get('signature'):
            payload = f"{encrypted_data['encrypted_payload']}:{encrypted_data['iv']}"
            signature_valid = self.verify_signature(payload, encrypted_data['signature'], sender_public_key)
        
        return {'plaintext': plaintext, 'signature_valid': signature_valid}
