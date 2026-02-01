"""
RSA Cryptography Module
=======================
Implemented by:
    - Amir (RSA Key Exchange Specialist): Key generation, RSA-OAEP encryption/decryption
    - Yong Cheng (Digital Signatures Specialist): RSA-PSS signing/verification

Provides:
    - KEY EXCHANGE: RSA-OAEP encryption/decryption
    - NON-REPUDIATION AT REST: RSA-PSS digital signatures

RSA-2048 is used for all operations.

Functions:
    Key Generation:
        - generate_rsa_keypair: Create new RSA-2048 key pair [Amir]
        
    Encryption (RSA-OAEP):
        - rsa_encrypt: Encrypt data with public key [Amir]
        - rsa_decrypt: Decrypt data with private key [Amir]
        
    Signatures (RSA-PSS):
        - rsa_sign: Sign data with private key [Yong Cheng]
        - rsa_verify: Verify signature with public key [Yong Cheng]
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature


# Constants
RSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537


def generate_rsa_keypair() -> tuple[str, str]:
    """
    Generate a new RSA-2048 key pair. [Amir]
    
    Returns:
        tuple: (private_key_pem, public_key_pem)
        Both keys are in PEM format (strings)
    """
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE
    )
    
    # Serialize private key to PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    # Serialize public key to PEM
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_pem, public_pem


# =============================================================================
# RSA-OAEP ENCRYPTION (for Key Exchange) - Amir
# =============================================================================

def rsa_encrypt(data: bytes, public_key_pem: str) -> bytes:
    """
    Encrypt data using RSA-OAEP with SHA-256. [Amir]
    
    Used to encrypt AES keys for recipients.
    
    Args:
        data: Data to encrypt (max ~190 bytes for RSA-2048)
        public_key_pem: Recipient's public key in PEM format
        
    Returns:
        bytes: Encrypted data (256 bytes for RSA-2048)
    """
    # Load public key from PEM
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8')
    )
    
    # Encrypt using OAEP padding
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return ciphertext


def rsa_decrypt(ciphertext: bytes, private_key_pem: str) -> bytes:
    """
    Decrypt data using RSA-OAEP with SHA-256. [Amir]
    
    Used to decrypt AES keys.
    
    Args:
        ciphertext: Data encrypted with RSA-OAEP
        private_key_pem: Your private key in PEM format
        
    Returns:
        bytes: Decrypted data (the original AES key)
    """
    # Load private key from PEM
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None
    )
    
    # Decrypt using OAEP padding
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return plaintext


# =============================================================================
# RSA-PSS SIGNATURES (for Non-Repudiation) - Yong Cheng
# =============================================================================

def rsa_sign(data: bytes, private_key_pem: str) -> bytes:
    """
    Sign data using RSA-PSS with SHA-256. [Yong Cheng]
    
    Creates a digital signature proving you created/approved this data.
    Used for NON-REPUDIATION - sender cannot deny sending the message.
    
    Args:
        data: Data to sign (typically: ciphertext + nonce)
        private_key_pem: Your private key in PEM format
        
    Returns:
        bytes: Digital signature (256 bytes for RSA-2048)
    """
    # Load private key from PEM
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None
    )
    
    # Sign using PSS padding (more secure than PKCS1v15)
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return signature


def rsa_verify(data: bytes, signature: bytes, public_key_pem: str) -> bool:
    """
    Verify RSA-PSS signature. [Yong Cheng]
    
    Confirms that the data was signed by the holder of the private key.
    Used to verify message authenticity and non-repudiation.
    
    Args:
        data: The original data that was signed
        signature: The signature to verify
        public_key_pem: Sender's public key in PEM format
        
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        # Load public key from PEM
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8')
        )
        
        # Verify signature
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return True
        
    except InvalidSignature:
        return False
    except Exception:
        return False
