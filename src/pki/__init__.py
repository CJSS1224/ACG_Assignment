"""
PKI (Public Key Infrastructure) Module - Member 6: [Name]

This module handles all key management operations including:
- RSA key pair generation
- X.509 certificate creation and validation
- Secure key storage and loading
- Session key generation and exchange

Key Management Responsibilities:
    - Generate and store RSA key pairs for clients
    - Create certificates signed by the Certificate Authority (CA)
    - Verify certificate chains and validity
    - Securely exchange symmetric keys using RSA encryption

PKI Architecture:
    - Self-signed CA certificate (root of trust)
    - Server certificate signed by CA
    - Client certificates signed by CA
    - Each entity has its own RSA key pair
"""



from src.pki.key_management import (
    generate_rsa_keypair,
    save_private_key,
    save_public_key,
    load_private_key,
    load_public_key,
    generate_certificate,
    verify_certificate
)
