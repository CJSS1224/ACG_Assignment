"""
Key Management Tests - Member 6: [Name]

Unit tests for the key management module to verify:
- RSA key pair generation
- Key serialization and storage
- Certificate operations
- Session key exchange

Run with: python -m pytest src/tests/test_key_management.py -v
"""

import unittest
import tempfile
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.pki.key_management import (
    generate_rsa_keypair,
    serialize_private_key,
    serialize_public_key,
    save_private_key,
    save_public_key,
    load_private_key,
    load_public_key,
    public_key_to_pem_string,
    pem_string_to_public_key,
    generate_ca_certificate,
    generate_certificate,
    save_certificate,
    load_certificate,
    verify_certificate,
    get_certificate_common_name,
    generate_session_key,
    encrypt_session_key,
    decrypt_session_key
)
from src.utils.constants import RSA_KEY_SIZE, AES_KEY_SIZE


class TestRSAKeyGeneration(unittest.TestCase):
    """Tests for RSA key pair generation."""
    
    def test_generate_keypair(self):
        """Test key pair generation."""
        private_key, public_key = generate_rsa_keypair()
        
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)
    
    def test_keypair_sizes(self):
        """Test that keys are correct size."""
        private_key, public_key = generate_rsa_keypair()
        
        # Check key size
        self.assertEqual(private_key.key_size, RSA_KEY_SIZE)
        self.assertEqual(public_key.key_size, RSA_KEY_SIZE)
    
    def test_keypairs_unique(self):
        """Test that each key pair is unique."""
        private1, public1 = generate_rsa_keypair()
        private2, public2 = generate_rsa_keypair()
        
        # Serialize and compare
        pem1 = serialize_public_key(public1)
        pem2 = serialize_public_key(public2)
        
        self.assertNotEqual(pem1, pem2)


class TestKeySerialization(unittest.TestCase):
    """Tests for key serialization."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.private_key, self.public_key = generate_rsa_keypair()
    
    def test_serialize_private_key_with_password(self):
        """Test private key serialization with password."""
        password = b"test_password"
        pem = serialize_private_key(self.private_key, password)
        
        # Should be PEM format
        self.assertTrue(pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"))
    
    def test_serialize_private_key_without_password(self):
        """Test private key serialization without password."""
        pem = serialize_private_key(self.private_key, None)
        
        # Should be PEM format (unencrypted)
        self.assertTrue(pem.startswith(b"-----BEGIN PRIVATE KEY-----"))
    
    def test_serialize_public_key(self):
        """Test public key serialization."""
        pem = serialize_public_key(self.public_key)
        
        # Should be PEM format
        self.assertTrue(pem.startswith(b"-----BEGIN PUBLIC KEY-----"))


class TestKeyStorage(unittest.TestCase):
    """Tests for key storage operations."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.private_key, self.public_key = generate_rsa_keypair()
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_save_and_load_private_key(self):
        """Test saving and loading private key."""
        filepath = os.path.join(self.temp_dir, "test_private.pem")
        password = b"test_password"
        
        # Save
        save_private_key(self.private_key, filepath, password)
        self.assertTrue(os.path.exists(filepath))
        
        # Load
        loaded_key = load_private_key(filepath, password)
        
        # Verify it's the same key by checking a signature
        from src.crypto.signatures import sign_message, verify_signature
        message = b"Test message"
        
        signature = sign_message(message, loaded_key)
        is_valid = verify_signature(message, signature, self.public_key)
        
        self.assertTrue(is_valid)
    
    def test_save_and_load_public_key(self):
        """Test saving and loading public key."""
        filepath = os.path.join(self.temp_dir, "test_public.pem")
        
        # Save
        save_public_key(self.public_key, filepath)
        self.assertTrue(os.path.exists(filepath))
        
        # Load
        loaded_key = load_public_key(filepath)
        
        # Verify it's the same key
        original_pem = serialize_public_key(self.public_key)
        loaded_pem = serialize_public_key(loaded_key)
        
        self.assertEqual(original_pem, loaded_pem)
    
    def test_load_private_key_wrong_password(self):
        """Test that wrong password fails."""
        filepath = os.path.join(self.temp_dir, "test_private.pem")
        password = b"correct_password"
        wrong_password = b"wrong_password"
        
        save_private_key(self.private_key, filepath, password)
        
        # LEARN: Wrong password should raise an exception
        with self.assertRaises(Exception):
            load_private_key(filepath, wrong_password)


class TestPEMStringConversion(unittest.TestCase):
    """Tests for PEM string conversion functions."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.private_key, self.public_key = generate_rsa_keypair()
    
    def test_public_key_to_pem_string(self):
        """Test converting public key to PEM string."""
        pem_string = public_key_to_pem_string(self.public_key)
        
        self.assertIsInstance(pem_string, str)
        self.assertTrue(pem_string.startswith("-----BEGIN PUBLIC KEY-----"))
    
    def test_pem_string_roundtrip(self):
        """Test PEM string conversion roundtrip."""
        pem_string = public_key_to_pem_string(self.public_key)
        recovered_key = pem_string_to_public_key(pem_string)
        
        # Compare serialized forms
        original_pem = serialize_public_key(self.public_key)
        recovered_pem = serialize_public_key(recovered_key)
        
        self.assertEqual(original_pem, recovered_pem)


class TestCertificates(unittest.TestCase):
    """Tests for certificate operations."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.ca_private, self.ca_public = generate_rsa_keypair()
        self.client_private, self.client_public = generate_rsa_keypair()
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_generate_ca_certificate(self):
        """Test CA certificate generation."""
        ca_cert = generate_ca_certificate(self.ca_private)
        
        self.assertIsNotNone(ca_cert)
        
        # Check it's a CA certificate
        from cryptography.x509 import ExtensionOID
        basic_constraints = ca_cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        self.assertTrue(basic_constraints.value.ca)
    
    def test_generate_client_certificate(self):
        """Test client certificate generation."""
        ca_cert = generate_ca_certificate(self.ca_private)
        
        client_cert = generate_certificate(
            subject_name="TestClient",
            subject_public_key=self.client_public,
            ca_private_key=self.ca_private,
            ca_certificate=ca_cert
        )
        
        self.assertIsNotNone(client_cert)
        
        # Check common name
        cn = get_certificate_common_name(client_cert)
        self.assertEqual(cn, "TestClient")
    
    def test_save_and_load_certificate(self):
        """Test certificate storage."""
        ca_cert = generate_ca_certificate(self.ca_private)
        filepath = os.path.join(self.temp_dir, "test_cert.pem")
        
        # Save
        save_certificate(ca_cert, filepath)
        self.assertTrue(os.path.exists(filepath))
        
        # Load
        loaded_cert = load_certificate(filepath)
        
        # Compare
        self.assertEqual(
            ca_cert.serial_number,
            loaded_cert.serial_number
        )
    
    def test_verify_certificate_success(self):
        """Test successful certificate verification."""
        ca_cert = generate_ca_certificate(self.ca_private)
        
        client_cert = generate_certificate(
            subject_name="TestClient",
            subject_public_key=self.client_public,
            ca_private_key=self.ca_private,
            ca_certificate=ca_cert
        )
        
        is_valid, msg = verify_certificate(client_cert, ca_cert)
        
        self.assertTrue(is_valid)
    
    def test_verify_certificate_wrong_ca(self):
        """Test certificate verification with wrong CA."""
        # Create two different CAs
        ca1_private, ca1_public = generate_rsa_keypair()
        ca2_private, ca2_public = generate_rsa_keypair()
        
        ca1_cert = generate_ca_certificate(ca1_private)
        ca2_cert = generate_ca_certificate(ca2_private)
        
        # Sign with CA1
        client_cert = generate_certificate(
            subject_name="TestClient",
            subject_public_key=self.client_public,
            ca_private_key=ca1_private,
            ca_certificate=ca1_cert
        )
        
        # Try to verify with CA2
        # LEARN: Certificate should only verify against the CA that signed it
        is_valid, msg = verify_certificate(client_cert, ca2_cert)
        
        self.assertFalse(is_valid)


class TestSessionKey(unittest.TestCase):
    """Tests for session key operations."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.private_key, self.public_key = generate_rsa_keypair()
    
    def test_generate_session_key(self):
        """Test session key generation."""
        session_key = generate_session_key()
        
        self.assertEqual(len(session_key), AES_KEY_SIZE)
    
    def test_session_key_uniqueness(self):
        """Test that session keys are unique."""
        keys = [generate_session_key() for _ in range(10)]
        unique_keys = set(keys)
        
        self.assertEqual(len(keys), len(unique_keys))
    
    def test_encrypt_decrypt_session_key(self):
        """Test session key encryption and decryption."""
        session_key = generate_session_key()
        
        # Encrypt with public key
        encrypted = encrypt_session_key(session_key, self.public_key)
        
        # Should be different from original
        self.assertNotEqual(encrypted, session_key)
        
        # Decrypt with private key
        decrypted = decrypt_session_key(encrypted, self.private_key)
        
        # Should match original
        self.assertEqual(decrypted, session_key)
    
    def test_session_key_wrong_private_key(self):
        """Test that wrong private key fails to decrypt."""
        other_private, other_public = generate_rsa_keypair()
        
        session_key = generate_session_key()
        encrypted = encrypt_session_key(session_key, self.public_key)
        
        # LEARN: Only the matching private key can decrypt
        with self.assertRaises(Exception):
            decrypt_session_key(encrypted, other_private)


if __name__ == '__main__':
    unittest.main()
