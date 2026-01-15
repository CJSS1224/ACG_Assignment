#!/usr/bin/env python3
"""
CA Setup Script

This script initializes the Certificate Authority (CA) for the secure
messaging system. Run this ONCE before starting the server for the first time.

What it creates:
1. CA private key (ca_private_key.pem)
2. CA certificate (ca_certificate.pem)
3. Server private key (server_private_key.pem)
4. Server certificate (server_certificate.pem)

Usage:
    python scripts/setup_ca.py

After running this script, you can start the server.
"""

import os
import sys

# LEARN: This adds the parent directory to Python's path
# LEARN: so we can import from the 'src' package
# LEARN: sys.path is a list of directories Python searches for modules
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(script_dir)
sys.path.insert(0, project_root)

from src.utils.constants import (
    CA_CERTIFICATE_PATH,
    CA_PRIVATE_KEY_PATH,
    SERVER_CERTIFICATE_PATH,
    SERVER_PRIVATE_KEY_PATH,
    SERVER_COMMON_NAME,
    CERTS_DIR,
    CA_CERTS_DIR,
    SERVER_CERTS_DIR
)
from src.utils.helpers import ensure_directory_exists, file_exists
from src.pki.key_management import (
    generate_rsa_keypair,
    generate_ca_certificate,
    generate_certificate,
    save_private_key,
    save_certificate,
    load_private_key,
    load_certificate
)


def print_header(text: str) -> None:
    """Print a formatted header."""
    print("\n" + "=" * 60)
    print(f" {text}")
    print("=" * 60)


def print_status(text: str, success: bool = True) -> None:
    """Print a status message with checkmark or X."""
    symbol = "✓" if success else "✗"
    print(f"  [{symbol}] {text}")


def setup_directories() -> None:
    """Create all necessary directories."""
    print_header("Setting up directories")
    
    directories = [CERTS_DIR, CA_CERTS_DIR, SERVER_CERTS_DIR]
    
    for directory in directories:
        ensure_directory_exists(directory)
        print_status(f"Directory ready: {directory}")


def setup_ca() -> tuple:
    """
    Set up the Certificate Authority.
    
    Returns:
        Tuple of (ca_private_key, ca_certificate)
    """
    print_header("Setting up Certificate Authority (CA)")
    
    # Check if CA already exists
    if file_exists(CA_PRIVATE_KEY_PATH) and file_exists(CA_CERTIFICATE_PATH):
        print_status("CA already exists, loading existing CA...")
        
        ca_private_key = load_private_key(CA_PRIVATE_KEY_PATH)
        ca_certificate = load_certificate(CA_CERTIFICATE_PATH)
        
        print_status("Loaded existing CA private key")
        print_status("Loaded existing CA certificate")
        
        return ca_private_key, ca_certificate
    
    # Generate new CA
    print_status("Generating new CA key pair...")
    ca_private_key, ca_public_key = generate_rsa_keypair()
    print_status("CA key pair generated (2048-bit RSA)")
    
    print_status("Generating CA certificate (self-signed)...")
    ca_certificate = generate_ca_certificate(ca_private_key)
    print_status("CA certificate generated")
    
    # Save CA files
    print_status("Saving CA private key...")
    save_private_key(ca_private_key, CA_PRIVATE_KEY_PATH)
    print_status(f"Saved to: {CA_PRIVATE_KEY_PATH}")
    
    print_status("Saving CA certificate...")
    save_certificate(ca_certificate, CA_CERTIFICATE_PATH)
    print_status(f"Saved to: {CA_CERTIFICATE_PATH}")
    
    return ca_private_key, ca_certificate


def setup_server_certificate(ca_private_key, ca_certificate) -> None:
    """
    Set up the server's certificate.
    
    Args:
        ca_private_key: CA's private key for signing
        ca_certificate: CA's certificate
    """
    print_header("Setting up Server Certificate")
    
    # Check if server cert already exists
    if file_exists(SERVER_PRIVATE_KEY_PATH) and file_exists(SERVER_CERTIFICATE_PATH):
        print_status("Server certificate already exists, skipping...")
        return
    
    # Generate server key pair
    print_status("Generating server key pair...")
    server_private_key, server_public_key = generate_rsa_keypair()
    print_status("Server key pair generated (2048-bit RSA)")
    
    # Generate server certificate (signed by CA)
    print_status("Generating server certificate (signed by CA)...")
    server_certificate = generate_certificate(
        subject_name=SERVER_COMMON_NAME,
        subject_public_key=server_public_key,
        ca_private_key=ca_private_key,
        ca_certificate=ca_certificate
    )
    print_status("Server certificate generated and signed by CA")
    
    # Save server files
    print_status("Saving server private key...")
    save_private_key(server_private_key, SERVER_PRIVATE_KEY_PATH)
    print_status(f"Saved to: {SERVER_PRIVATE_KEY_PATH}")
    
    print_status("Saving server certificate...")
    save_certificate(server_certificate, SERVER_CERTIFICATE_PATH)
    print_status(f"Saved to: {SERVER_CERTIFICATE_PATH}")


def print_summary() -> None:
    """Print a summary of created files."""
    print_header("Setup Complete!")
    
    print("\nCreated files:")
    print(f"  • CA Private Key:      {CA_PRIVATE_KEY_PATH}")
    print(f"  • CA Certificate:      {CA_CERTIFICATE_PATH}")
    print(f"  • Server Private Key:  {SERVER_PRIVATE_KEY_PATH}")
    print(f"  • Server Certificate:  {SERVER_CERTIFICATE_PATH}")
    
    print("\n" + "-" * 60)
    print(" SECURITY NOTES:")
    print("-" * 60)
    print("  • The CA private key is the root of trust.")
    print("  • In production, protect it with a strong password")
    print("    and store it offline.")
    print("  • Never share private keys!")
    print("  • Certificates (*.pem without 'private') are safe to share.")
    print("-" * 60)
    
    print("\nNext steps:")
    print("  1. Start the server:  python -m src.server.server")
    print("  2. Start client(s):   python -m src.client.client")
    print()


def main():
    """Main entry point for CA setup."""
    print("\n" + "=" * 60)
    print(" ST2504 Applied Cryptography - CA Setup Script")
    print(" Secure Messaging System")
    print("=" * 60)
    
    try:
        # Step 1: Create directories
        setup_directories()
        
        # Step 2: Set up CA
        ca_private_key, ca_certificate = setup_ca()
        
        # Step 3: Set up server certificate
        setup_server_certificate(ca_private_key, ca_certificate)
        
        # Step 4: Print summary
        print_summary()
        
        return 0
        
    except Exception as e:
        print(f"\n[ERROR] Setup failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
