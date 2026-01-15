#!/usr/bin/env python3
"""
Test Key Generation Script

This script generates test keys for development and testing purposes.
It creates key pairs and certificates for test users without needing
to run the full registration process.

Usage:
    python scripts/generate_test_keys.py [username1] [username2] ...

If no usernames provided, generates keys for: Alice, Bob, Charlie
"""

import os
import sys

# Add project root to path
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(script_dir)
sys.path.insert(0, project_root)

from src.utils.constants import (
    CA_PRIVATE_KEY_PATH,
    CA_CERTIFICATE_PATH,
    CLIENT_KEYS_DIR
)
from src.utils.helpers import ensure_directory_exists, file_exists
from src.pki.key_management import (
    load_private_key,
    load_certificate,
    setup_client_keys,
    client_keys_exist
)


def print_status(text: str, success: bool = True) -> None:
    """Print a status message."""
    symbol = "✓" if success else "✗"
    print(f"  [{symbol}] {text}")


def generate_keys_for_user(username: str, ca_private_key, ca_certificate) -> bool:
    """
    Generate keys for a test user.
    
    Args:
        username: Username for the test user
        ca_private_key: CA's private key
        ca_certificate: CA's certificate
        
    Returns:
        True if successful, False otherwise
    """
    if client_keys_exist(username):
        print_status(f"Keys already exist for '{username}', skipping...")
        return True
    
    try:
        print(f"\nGenerating keys for '{username}'...")
        
        private_key, public_key, certificate = setup_client_keys(
            username,
            ca_private_key,
            ca_certificate
        )
        
        print_status(f"Generated RSA key pair")
        print_status(f"Generated X.509 certificate")
        print_status(f"Saved to {CLIENT_KEYS_DIR}")
        
        return True
        
    except Exception as e:
        print_status(f"Failed: {str(e)}", success=False)
        return False


def main():
    """Main entry point."""
    print("\n" + "=" * 60)
    print(" ST2504 Applied Cryptography - Test Key Generator")
    print("=" * 60)
    
    # Get usernames from command line or use defaults
    if len(sys.argv) > 1:
        usernames = sys.argv[1:]
    else:
        usernames = ["Alice", "Bob", "Charlie"]
        print("\nNo usernames provided. Using defaults: Alice, Bob, Charlie")
    
    # Check if CA exists
    if not file_exists(CA_PRIVATE_KEY_PATH) or not file_exists(CA_CERTIFICATE_PATH):
        print("\n[ERROR] CA not initialized!")
        print("Please run 'python scripts/setup_ca.py' first.")
        return 1
    
    # Load CA
    print("\nLoading Certificate Authority...")
    try:
        ca_private_key = load_private_key(CA_PRIVATE_KEY_PATH)
        ca_certificate = load_certificate(CA_CERTIFICATE_PATH)
        print_status("CA loaded successfully")
    except Exception as e:
        print_status(f"Failed to load CA: {e}", success=False)
        return 1
    
    # Create directory
    ensure_directory_exists(CLIENT_KEYS_DIR)
    
    # Generate keys for each user
    success_count = 0
    for username in usernames:
        if generate_keys_for_user(username, ca_private_key, ca_certificate):
            success_count += 1
    
    # Summary
    print("\n" + "-" * 60)
    print(f" Generated keys for {success_count}/{len(usernames)} users")
    print("-" * 60)
    
    print("\nGenerated files location:")
    print(f"  {CLIENT_KEYS_DIR}/")
    for username in usernames:
        if client_keys_exist(username):
            print(f"    - {username}_private.pem")
            print(f"    - {username}_public.pem")
            print(f"    - {username}_certificate.pem")
    
    print("\nThese keys can be used for testing without running the full")
    print("client registration process.")
    print()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
