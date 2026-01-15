"""
Signatures Tests - Member 5: [Name]

Unit tests for the signatures module to verify:
- Digital signature creation
- Signature verification
- Non-repudiation properties

Run with: python -m pytest src/tests/test_signatures.py -v
"""

import unittest
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.crypto.signatures import (
    sign_message,
    sign_message_string,
    verify_signature,
    verify_signature_string,
    sign_with_timestamp,
    verify_with_timestamp,
    create_signed_package,
    verify_signed_package,
    get_signature_info,
    sign_multiple_messages,
    verify_multiple_messages
)
from src.pki.key_management import generate_rsa_keypair


class TestSignatureBasic(unittest.TestCase):
    """Basic tests for digital signatures."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.private_key, self.public_key = generate_rsa_keypair()
        self.message = b"Test message for signing"
    
    def test_signature_creation(self):
        """Test that signature can be created."""
        signature = sign_message(self.message, self.private_key)
        
        # LEARN: For 2048-bit RSA, signature is 256 bytes
        self.assertEqual(len(signature), 256)
    
    def test_signature_verification_success(self):
        """Test successful signature verification."""
        signature = sign_message(self.message, self.private_key)
        is_valid = verify_signature(self.message, signature, self.public_key)
        
        self.assertTrue(is_valid)
    
    def test_signature_verification_failure_wrong_key(self):
        """Test that verification fails with wrong public key."""
        # Generate different key pair
        other_private, other_public = generate_rsa_keypair()
        
        signature = sign_message(self.message, self.private_key)
        
        # LEARN: Signature should only verify with the matching public key
        is_valid = verify_signature(self.message, signature, other_public)
        self.assertFalse(is_valid)
    
    def test_signature_verification_failure_tampered_message(self):
        """Test that verification fails when message is tampered."""
        signature = sign_message(self.message, self.private_key)
        tampered_message = b"Tampered message"
        
        # LEARN: This is the integrity property of signatures
        is_valid = verify_signature(tampered_message, signature, self.public_key)
        self.assertFalse(is_valid)
    
    def test_signature_verification_failure_tampered_signature(self):
        """Test that verification fails when signature is tampered."""
        signature = sign_message(self.message, self.private_key)
        
        # Tamper with signature
        tampered_signature = bytes([b ^ 0xFF for b in signature])
        
        is_valid = verify_signature(self.message, tampered_signature, self.public_key)
        self.assertFalse(is_valid)


class TestSignatureString(unittest.TestCase):
    """Tests for string-based signature functions."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.private_key, self.public_key = generate_rsa_keypair()
        self.message = "String message for signing"
    
    def test_string_signature_roundtrip(self):
        """Test string signature creation and verification."""
        signature = sign_message_string(self.message, self.private_key)
        is_valid = verify_signature_string(self.message, signature, self.public_key)
        
        self.assertTrue(is_valid)
    
    def test_string_signature_is_base64(self):
        """Test that string signature is valid Base64."""
        import base64
        signature = sign_message_string(self.message, self.private_key)
        
        # Should not raise exception
        decoded = base64.b64decode(signature)
        self.assertEqual(len(decoded), 256)


class TestSignatureWithTimestamp(unittest.TestCase):
    """Tests for timestamped signatures."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.private_key, self.public_key = generate_rsa_keypair()
        self.message = "Timestamped message"
        self.timestamp = 1704067200.0  # Fixed timestamp for testing
    
    def test_timestamped_signature_verification(self):
        """Test timestamped signature verification."""
        signature, signed_data = sign_with_timestamp(
            self.message,
            self.private_key,
            self.timestamp
        )
        
        is_valid = verify_with_timestamp(
            self.message,
            self.timestamp,
            signature,
            self.public_key
        )
        
        self.assertTrue(is_valid)
    
    def test_timestamped_signature_wrong_timestamp_fails(self):
        """Test that wrong timestamp fails verification."""
        signature, signed_data = sign_with_timestamp(
            self.message,
            self.private_key,
            self.timestamp
        )
        
        # Try to verify with different timestamp
        wrong_timestamp = self.timestamp + 1
        is_valid = verify_with_timestamp(
            self.message,
            wrong_timestamp,
            signature,
            self.public_key
        )
        
        # LEARN: Timestamp is bound to the signature - can't change it
        self.assertFalse(is_valid)


class TestSignedPackage(unittest.TestCase):
    """Tests for signed package (at-rest storage)."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.private_key, self.public_key = generate_rsa_keypair()
        self.message = "Message for storage"
        self.sender = "TestUser"
    
    def test_create_signed_package(self):
        """Test signed package creation."""
        package = create_signed_package(
            self.message,
            self.sender,
            self.private_key
        )
        
        # Check all expected fields exist
        self.assertIn('message', package)
        self.assertIn('sender', package)
        self.assertIn('timestamp', package)
        self.assertIn('signature', package)
        self.assertIn('algorithm', package)
        
        # Check values
        self.assertEqual(package['message'], self.message)
        self.assertEqual(package['sender'], self.sender)
    
    def test_verify_signed_package_success(self):
        """Test successful signed package verification."""
        package = create_signed_package(
            self.message,
            self.sender,
            self.private_key
        )
        
        is_valid, msg = verify_signed_package(package, self.public_key)
        
        self.assertTrue(is_valid)
        self.assertIn("valid", msg.lower())
    
    def test_verify_signed_package_tampered_message(self):
        """Test that tampered package is detected."""
        package = create_signed_package(
            self.message,
            self.sender,
            self.private_key
        )
        
        # Tamper with message
        package['message'] = "Tampered message"
        
        is_valid, msg = verify_signed_package(package, self.public_key)
        
        self.assertFalse(is_valid)
    
    def test_verify_signed_package_wrong_sender(self):
        """Test that wrong sender claim is detected."""
        package = create_signed_package(
            self.message,
            self.sender,
            self.private_key
        )
        
        # Try to claim different sender
        package['sender'] = "FakeSender"
        
        is_valid, msg = verify_signed_package(package, self.public_key)
        
        # LEARN: Non-repudiation - can't change who sent the message
        self.assertFalse(is_valid)


class TestNonRepudiation(unittest.TestCase):
    """Tests demonstrating non-repudiation property."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.alice_private, self.alice_public = generate_rsa_keypair()
        self.bob_private, self.bob_public = generate_rsa_keypair()
    
    def test_sender_cannot_deny(self):
        """Test that sender cannot deny sending a message."""
        message = b"I agree to pay $1000"
        
        # Alice signs the message
        alice_signature = sign_message(message, self.alice_private)
        
        # Anyone can verify Alice signed it using her public key
        is_alice_signature = verify_signature(message, alice_signature, self.alice_public)
        is_bob_signature = verify_signature(message, alice_signature, self.bob_public)
        
        # LEARN: Only verifies with Alice's key - proves she signed it
        self.assertTrue(is_alice_signature)
        self.assertFalse(is_bob_signature)
    
    def test_others_cannot_forge(self):
        """Test that others cannot forge Alice's signature."""
        message = b"Important document"
        
        # Bob tries to create signature claiming to be Alice
        bob_forged_signature = sign_message(message, self.bob_private)
        
        # Verification with Alice's public key should fail
        # LEARN: Only Alice's private key can create valid signatures
        is_valid = verify_signature(message, bob_forged_signature, self.alice_public)
        self.assertFalse(is_valid)


class TestBatchSigning(unittest.TestCase):
    """Tests for batch signing operations."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.private_key, self.public_key = generate_rsa_keypair()
        self.messages = [
            "Message 1",
            "Message 2",
            "Message 3",
        ]
    
    def test_sign_multiple_messages(self):
        """Test signing multiple messages."""
        results = sign_multiple_messages(self.messages, self.private_key)
        
        self.assertEqual(len(results), len(self.messages))
        
        for msg, sig in results:
            self.assertIn(msg, self.messages)
            self.assertIsInstance(sig, str)  # Base64 string
    
    def test_verify_multiple_messages(self):
        """Test verifying multiple signatures."""
        signed = sign_multiple_messages(self.messages, self.private_key)
        verified = verify_multiple_messages(signed, self.public_key)
        
        for msg, is_valid in verified:
            self.assertTrue(is_valid)


class TestSignatureInfo(unittest.TestCase):
    """Tests for signature algorithm information."""
    
    def test_get_signature_info(self):
        """Test getting signature algorithm info."""
        info = get_signature_info()
        
        self.assertEqual(info['algorithm'], 'RSA')
        self.assertEqual(info['padding'], 'PKCS#1 v1.5')
        self.assertEqual(info['hash'], 'SHA-256')


if __name__ == '__main__':
    unittest.main()
