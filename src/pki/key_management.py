"""
Key Management Module - Member 6: [Name]

This module handles all Public Key Infrastructure (PKI) operations including:
- RSA key pair generation and storage
- X.509 certificate creation and validation
- Secure key loading with password protection
- Session key generation and exchange

Security Properties Provided:
- Asymmetric encryption enables secure key exchange
- Certificates provide identity verification
- Password-protected private keys prevent unauthorized access

Dependencies:
    - cryptography library for all cryptographic operations
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Tuple, Optional

# LEARN: The 'cryptography' library is the recommended Python library for crypto
# LEARN: It's maintained by the Python Cryptographic Authority and well-audited
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import (
    CertificateBuilder,
    Name,
    NameAttribute,
    BasicConstraints,
    SubjectKeyIdentifier,
    AuthorityKeyIdentifier,
    random_serial_number,
    load_pem_x509_certificate
)
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from src.utils.constants import (
    RSA_KEY_SIZE,
    AES_KEY_SIZE,
    CERT_VALIDITY_DAYS,
    CA_COUNTRY,
    CA_STATE,
    CA_LOCALITY,
    CA_ORGANIZATION,
    CA_COMMON_NAME,
    DEFAULT_KEY_PASSWORD,
    CA_CERTIFICATE_PATH,
    CA_PRIVATE_KEY_PATH,
    CLIENT_KEYS_DIR
)
from src.utils.helpers import (
    ensure_directory_exists,
    file_exists,
    generate_random_bytes,
    bytes_to_base64,
    base64_to_bytes
)


# =============================================================================
# RSA KEY PAIR GENERATION
# =============================================================================

def generate_rsa_keypair(key_size: int = RSA_KEY_SIZE) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generate a new RSA key pair.
    
    RSA is an asymmetric encryption algorithm where:
    - The public key can be shared with anyone
    - The private key must be kept secret
    - Data encrypted with public key can only be decrypted with private key
    - Data signed with private key can be verified with public key
    
    Args:
        key_size: Size of the key in bits (default: 2048)
        
    Returns:
        Tuple of (private_key, public_key)
    """
    # LEARN: RSA key generation explained:
    # LEARN: 1. Choose two large prime numbers p and q
    # LEARN: 2. Compute n = p * q (this becomes part of both keys)
    # LEARN: 3. Compute φ(n) = (p-1)(q-1) (Euler's totient)
    # LEARN: 4. Choose e (public exponent) - usually 65537
    # LEARN: 5. Compute d where d*e ≡ 1 (mod φ(n)) (private exponent)
    # LEARN: Public key = (n, e), Private key = (n, d)
    
    # LEARN: public_exponent=65537 is standard - it's a Fermat prime
    # LEARN: that makes encryption fast while remaining secure
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Standard public exponent (0x10001)
        key_size=key_size,
        backend=default_backend()
    )
    
    # LEARN: The public key is mathematically derived from the private key
    public_key = private_key.public_key()
    
    return private_key, public_key


# =============================================================================
# KEY SERIALIZATION (SAVING/LOADING)
# =============================================================================

def serialize_private_key(
    private_key: rsa.RSAPrivateKey,
    password: Optional[bytes] = None
) -> bytes:
    """
    Serialize a private key to PEM format.
    
    PEM (Privacy-Enhanced Mail) is a Base64-encoded format with headers.
    It looks like:
    -----BEGIN ENCRYPTED PRIVATE KEY-----
    MIIFHDBOBgkqhkiG9w0BBQ0wQTA...
    -----END ENCRYPTED PRIVATE KEY-----
    
    Args:
        private_key: RSA private key object
        password: Optional password for encryption (recommended!)
        
    Returns:
        PEM-encoded private key as bytes
    """
    # LEARN: Private keys should ALWAYS be encrypted when stored
    # LEARN: Even if an attacker gets the file, they can't use it without password
    
    if password:
        # LEARN: BestAvailableEncryption uses AES-256-CBC with PBKDF2 key derivation
        # LEARN: This is the strongest encryption available for key storage
        encryption = serialization.BestAvailableEncryption(password)
    else:
        # LEARN: NoEncryption stores the key in plain text - NOT recommended!
        encryption = serialization.NoEncryption()
    
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,  # Modern standard format
        encryption_algorithm=encryption
    )


def serialize_public_key(public_key: rsa.RSAPublicKey) -> bytes:
    """
    Serialize a public key to PEM format.
    
    Public keys don't need encryption since they're meant to be shared.
    
    Args:
        public_key: RSA public key object
        
    Returns:
        PEM-encoded public key as bytes
    """
    # LEARN: Public keys are safe to share - that's their purpose
    # LEARN: Anyone can use them to encrypt data for you or verify your signatures
    
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def save_private_key(
    private_key: rsa.RSAPrivateKey,
    filepath: str,
    password: Optional[bytes] = DEFAULT_KEY_PASSWORD
) -> None:
    """
    Save a private key to a file.
    
    Args:
        private_key: RSA private key to save
        filepath: Path to save the key file
        password: Password for encrypting the key
    """
    ensure_directory_exists(os.path.dirname(filepath))
    
    pem_data = serialize_private_key(private_key, password)
    
    with open(filepath, 'wb') as f:
        f.write(pem_data)


def save_public_key(public_key: rsa.RSAPublicKey, filepath: str) -> None:
    """
    Save a public key to a file.
    
    Args:
        public_key: RSA public key to save
        filepath: Path to save the key file
    """
    ensure_directory_exists(os.path.dirname(filepath))
    
    pem_data = serialize_public_key(public_key)
    
    with open(filepath, 'wb') as f:
        f.write(pem_data)


def load_private_key(
    filepath: str,
    password: Optional[bytes] = DEFAULT_KEY_PASSWORD
) -> rsa.RSAPrivateKey:
    """
    Load a private key from a file.
    
    Args:
        filepath: Path to the key file
        password: Password to decrypt the key
        
    Returns:
        RSA private key object
        
    Raises:
        ValueError: If password is incorrect
        FileNotFoundError: If file doesn't exist
    """
    # LEARN: When loading an encrypted key, you must provide the same password
    # LEARN: used when saving it. Wrong password = ValueError exception
    
    with open(filepath, 'rb') as f:
        pem_data = f.read()
    
    return serialization.load_pem_private_key(
        pem_data,
        password=password,
        backend=default_backend()
    )


def load_public_key(filepath: str) -> rsa.RSAPublicKey:
    """
    Load a public key from a file.
    
    Args:
        filepath: Path to the key file
        
    Returns:
        RSA public key object
    """
    with open(filepath, 'rb') as f:
        pem_data = f.read()
    
    return serialization.load_pem_public_key(
        pem_data,
        backend=default_backend()
    )


def public_key_to_pem_string(public_key: rsa.RSAPublicKey) -> str:
    """
    Convert a public key to a PEM string for transmission.
    
    Args:
        public_key: RSA public key object
        
    Returns:
        PEM-encoded public key as a string
    """
    return serialize_public_key(public_key).decode('utf-8')


def pem_string_to_public_key(pem_string: str) -> rsa.RSAPublicKey:
    """
    Convert a PEM string back to a public key object.
    
    Args:
        pem_string: PEM-encoded public key string
        
    Returns:
        RSA public key object
    """
    return serialization.load_pem_public_key(
        pem_string.encode('utf-8'),
        backend=default_backend()
    )


# =============================================================================
# X.509 CERTIFICATE OPERATIONS
# =============================================================================

def generate_ca_certificate(
    private_key: rsa.RSAPrivateKey,
    validity_days: int = CERT_VALIDITY_DAYS
) -> 'Certificate':
    """
    Generate a self-signed Certificate Authority (CA) certificate.
    
    The CA certificate is the root of trust. All other certificates are
    signed by the CA and can be verified against this certificate.
    
    Args:
        private_key: CA's private key (used to self-sign the certificate)
        validity_days: How many days the certificate is valid
        
    Returns:
        X.509 certificate object
    """
    # LEARN: X.509 is the standard format for public key certificates
    # LEARN: A certificate binds a public key to an identity (subject name)
    # LEARN: The CA certificate is special - it signs itself (self-signed)
    
    # LEARN: The subject and issuer are the same for self-signed certificates
    subject = issuer = Name([
        NameAttribute(NameOID.COUNTRY_NAME, CA_COUNTRY),
        NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, CA_STATE),
        NameAttribute(NameOID.LOCALITY_NAME, CA_LOCALITY),
        NameAttribute(NameOID.ORGANIZATION_NAME, CA_ORGANIZATION),
        NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME),
    ])
    
    # LEARN: Certificate validity period
    now = datetime.now(timezone.utc)
    
    # Build the certificate
    cert_builder = CertificateBuilder()
    cert_builder = cert_builder.subject_name(subject)
    cert_builder = cert_builder.issuer_name(issuer)
    cert_builder = cert_builder.public_key(private_key.public_key())
    cert_builder = cert_builder.serial_number(random_serial_number())
    cert_builder = cert_builder.not_valid_before(now)
    cert_builder = cert_builder.not_valid_after(now + timedelta(days=validity_days))
    
    # LEARN: BasicConstraints extension marks this as a CA certificate
    # LEARN: ca=True means this certificate can sign other certificates
    cert_builder = cert_builder.add_extension(
        BasicConstraints(ca=True, path_length=None),
        critical=True
    )
    
    # LEARN: SubjectKeyIdentifier helps identify this certificate
    # LEARN: It's a hash of the public key
    cert_builder = cert_builder.add_extension(
        SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False
    )
    
    # LEARN: Sign the certificate with the CA's private key
    # LEARN: SHA256 is the hash algorithm used in the signature
    certificate = cert_builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    
    return certificate


def generate_certificate(
    subject_name: str,
    subject_public_key: rsa.RSAPublicKey,
    ca_private_key: rsa.RSAPrivateKey,
    ca_certificate: 'Certificate',
    validity_days: int = CERT_VALIDITY_DAYS
) -> 'Certificate':
    """
    Generate a certificate signed by the CA.
    
    This is used to create certificates for the server and clients.
    
    Args:
        subject_name: Common name for the certificate (e.g., username)
        subject_public_key: Public key of the entity getting the certificate
        ca_private_key: CA's private key (used to sign)
        ca_certificate: CA's certificate (provides issuer info)
        validity_days: How many days the certificate is valid
        
    Returns:
        X.509 certificate object
    """
    # LEARN: Unlike the CA cert, this certificate is NOT self-signed
    # LEARN: The issuer is the CA, and the subject is the entity (server/client)
    
    subject = Name([
        NameAttribute(NameOID.COUNTRY_NAME, CA_COUNTRY),
        NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, CA_STATE),
        NameAttribute(NameOID.ORGANIZATION_NAME, CA_ORGANIZATION),
        NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])
    
    # LEARN: The issuer is taken from the CA certificate
    issuer = ca_certificate.subject
    
    now = datetime.now(timezone.utc)
    
    cert_builder = CertificateBuilder()
    cert_builder = cert_builder.subject_name(subject)
    cert_builder = cert_builder.issuer_name(issuer)
    cert_builder = cert_builder.public_key(subject_public_key)
    cert_builder = cert_builder.serial_number(random_serial_number())
    cert_builder = cert_builder.not_valid_before(now)
    cert_builder = cert_builder.not_valid_after(now + timedelta(days=validity_days))
    
    # LEARN: ca=False means this is an end-entity certificate
    # LEARN: It cannot be used to sign other certificates
    cert_builder = cert_builder.add_extension(
        BasicConstraints(ca=False, path_length=None),
        critical=True
    )
    
    # Subject Key Identifier
    cert_builder = cert_builder.add_extension(
        SubjectKeyIdentifier.from_public_key(subject_public_key),
        critical=False
    )
    
    # LEARN: Authority Key Identifier links this cert to the CA cert
    # LEARN: It helps build the certificate chain for verification
    cert_builder = cert_builder.add_extension(
        AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
        critical=False
    )
    
    # Sign with CA's private key
    certificate = cert_builder.sign(
        private_key=ca_private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    
    return certificate


def save_certificate(certificate: 'Certificate', filepath: str) -> None:
    """
    Save a certificate to a PEM file.
    
    Args:
        certificate: X.509 certificate object
        filepath: Path to save the certificate
    """
    ensure_directory_exists(os.path.dirname(filepath))
    
    pem_data = certificate.public_bytes(serialization.Encoding.PEM)
    
    with open(filepath, 'wb') as f:
        f.write(pem_data)


def load_certificate(filepath: str) -> 'Certificate':
    """
    Load a certificate from a PEM file.
    
    Args:
        filepath: Path to the certificate file
        
    Returns:
        X.509 certificate object
    """
    with open(filepath, 'rb') as f:
        pem_data = f.read()
    
    return load_pem_x509_certificate(pem_data, default_backend())


def verify_certificate(
    certificate: 'Certificate',
    ca_certificate: 'Certificate'
) -> Tuple[bool, str]:
    """
    Verify that a certificate was signed by the CA and is still valid.
    
    Args:
        certificate: Certificate to verify
        ca_certificate: CA certificate to verify against
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    # LEARN: Certificate verification checks:
    # LEARN: 1. Was it signed by the CA? (signature verification)
    # LEARN: 2. Is it still valid? (not expired, not used before valid date)
    # LEARN: 3. Is the issuer correct? (chain of trust)
    
    try:
        # Check expiration
        now = datetime.now(timezone.utc)
        
        if now < certificate.not_valid_before_utc:
            return False, "Certificate is not yet valid"
        
        if now > certificate.not_valid_after_utc:
            return False, "Certificate has expired"
        
        # LEARN: Verify the signature on the certificate
        # LEARN: The CA's public key is used to verify the CA's signature
        ca_public_key = ca_certificate.public_key()
        
        # LEARN: This verifies that the CA actually signed this certificate
        ca_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,  # "to be signed" certificate data
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm
        )
        
        return True, "Certificate is valid"
        
    except Exception as e:
        return False, f"Certificate verification failed: {str(e)}"


def get_certificate_common_name(certificate: 'Certificate') -> str:
    """
    Extract the Common Name (CN) from a certificate.
    
    Args:
        certificate: X.509 certificate
        
    Returns:
        Common Name string (e.g., username)
    """
    # LEARN: The Common Name is typically the identity - username, domain name, etc.
    
    for attribute in certificate.subject:
        if attribute.oid == NameOID.COMMON_NAME:
            return attribute.value
    return ""


# =============================================================================
# SESSION KEY OPERATIONS
# =============================================================================

def generate_session_key() -> bytes:
    """
    Generate a random session key for AES encryption.
    
    Session keys are symmetric keys used for a single session.
    They're faster than RSA for bulk encryption.
    
    Returns:
        Random bytes suitable for AES-256 key
    """
    # LEARN: Symmetric encryption (AES) is much faster than asymmetric (RSA)
    # LEARN: So we use RSA only to exchange the symmetric key
    # LEARN: Then use AES for all actual message encryption
    # LEARN: This hybrid approach is used in TLS, PGP, and most crypto systems
    
    return generate_random_bytes(AES_KEY_SIZE)


def encrypt_session_key(session_key: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """
    Encrypt a session key with an RSA public key.
    
    This allows secure transmission of the session key.
    Only the holder of the corresponding private key can decrypt it.
    
    Args:
        session_key: The symmetric key to encrypt
        public_key: Recipient's RSA public key
        
    Returns:
        Encrypted session key
    """
    # LEARN: OAEP (Optimal Asymmetric Encryption Padding) is the recommended
    # LEARN: padding scheme for RSA encryption. It provides better security
    # LEARN: than the older PKCS#1 v1.5 padding.
    
    encrypted_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return encrypted_key


def decrypt_session_key(encrypted_key: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Decrypt a session key with an RSA private key.
    
    Args:
        encrypted_key: The encrypted session key
        private_key: Recipient's RSA private key
        
    Returns:
        Decrypted session key
    """
    session_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return session_key


# =============================================================================
# CLIENT KEY MANAGEMENT
# =============================================================================

def get_client_key_paths(username: str) -> Tuple[str, str]:
    """
    Get the file paths for a client's keys.
    
    Args:
        username: Client's username
        
    Returns:
        Tuple of (private_key_path, public_key_path)
    """
    private_key_path = os.path.join(CLIENT_KEYS_DIR, f"{username}_private.pem")
    public_key_path = os.path.join(CLIENT_KEYS_DIR, f"{username}_public.pem")
    
    return private_key_path, public_key_path


def get_client_certificate_path(username: str) -> str:
    """
    Get the file path for a client's certificate.
    
    Args:
        username: Client's username
        
    Returns:
        Certificate file path
    """
    return os.path.join(CLIENT_KEYS_DIR, f"{username}_certificate.pem")


def setup_client_keys(
    username: str,
    ca_private_key: rsa.RSAPrivateKey,
    ca_certificate: 'Certificate'
) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey, 'Certificate']:
    """
    Set up complete key infrastructure for a new client.
    
    This generates:
    - RSA key pair for the client
    - Certificate signed by the CA
    - Saves everything to disk
    
    Args:
        username: Client's username
        ca_private_key: CA's private key for signing
        ca_certificate: CA's certificate
        
    Returns:
        Tuple of (private_key, public_key, certificate)
    """
    # LEARN: This function is called when a new client registers
    # LEARN: It sets up everything the client needs for secure communication
    
    # Generate key pair
    private_key, public_key = generate_rsa_keypair()
    
    # Generate certificate
    certificate = generate_certificate(
        subject_name=username,
        subject_public_key=public_key,
        ca_private_key=ca_private_key,
        ca_certificate=ca_certificate
    )
    
    # Get file paths
    private_key_path, public_key_path = get_client_key_paths(username)
    cert_path = get_client_certificate_path(username)
    
    # Save to disk
    save_private_key(private_key, private_key_path)
    save_public_key(public_key, public_key_path)
    save_certificate(certificate, cert_path)
    
    return private_key, public_key, certificate


def load_client_keys(username: str) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Load an existing client's keys from disk.
    
    Args:
        username: Client's username
        
    Returns:
        Tuple of (private_key, public_key)
        
    Raises:
        FileNotFoundError: If keys don't exist
    """
    private_key_path, public_key_path = get_client_key_paths(username)
    
    private_key = load_private_key(private_key_path)
    public_key = load_public_key(public_key_path)
    
    return private_key, public_key


def client_keys_exist(username: str) -> bool:
    """
    Check if a client's keys already exist.
    
    Args:
        username: Client's username
        
    Returns:
        True if keys exist, False otherwise
    """
    private_key_path, public_key_path = get_client_key_paths(username)
    
    return file_exists(private_key_path) and file_exists(public_key_path)


# =============================================================================
# CA INITIALIZATION
# =============================================================================

def initialize_ca() -> Tuple[rsa.RSAPrivateKey, 'Certificate']:
    """
    Initialize the Certificate Authority.
    
    If CA keys already exist, load them. Otherwise, generate new ones.
    
    Returns:
        Tuple of (ca_private_key, ca_certificate)
    """
    # LEARN: The CA should only be initialized once
    # LEARN: After that, we load the existing CA keys
    
    if file_exists(CA_PRIVATE_KEY_PATH) and file_exists(CA_CERTIFICATE_PATH):
        # Load existing CA
        ca_private_key = load_private_key(CA_PRIVATE_KEY_PATH)
        ca_certificate = load_certificate(CA_CERTIFICATE_PATH)
        print("[PKI] Loaded existing CA certificate and key")
    else:
        # Generate new CA
        print("[PKI] Generating new CA certificate and key...")
        ca_private_key, ca_public_key = generate_rsa_keypair()
        ca_certificate = generate_ca_certificate(ca_private_key)
        
        # Save CA files
        save_private_key(ca_private_key, CA_PRIVATE_KEY_PATH)
        save_certificate(ca_certificate, CA_CERTIFICATE_PATH)
        print(f"[PKI] CA certificate saved to {CA_CERTIFICATE_PATH}")
    
    return ca_private_key, ca_certificate
