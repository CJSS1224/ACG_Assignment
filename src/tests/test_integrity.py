"""
Integrity Tests - Member 4: [Name]

Unit tests for the integrity module to verify:
- HMAC generation and verification
- Hash functions
- Nonce generation
- Timestamp validation

Run with: python -m pytest src/tests/test_integrity.py -v
"""

import unittest
import time
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.crypto.integrity import (
    generate_hmac_key,
    generate_hmac,
    generate_hmac_string,
    verify_hmac,
    verify_hmac_string,
    hash_sha256,
    hash_sha256_string,
    hash_message,
    generate_nonce,
    generate_nonce_string,
    check_and_record_nonce,
    clear_nonce_cache,
    create_timestamp,
    verify_timestamp,
    create_integrity_data,
    verify_integrity_data,
    hash_password,
    verify_password
)
from src.utils.constants import HMAC_KEY_SIZE, NONCE_SIZE


class TestHMACKeyGeneration(unittest.TestCase):
    """Tests for HMAC key generation."""
    
    def test_key_length(self):
        """Test that generated key is correct length."""
        key = generate_hmac_key()
        self.assertEqual(len(key), HMAC_KEY_SIZE)
    
    def test_key_randomness(self):
        """Test that keys are unique."""
        key1 = generate_hmac_key()
        key2 = generate_hmac_key()
        self.assertNotEqual(key1, key2)


class TestHMACGeneration(unittest.TestCase):
    """Tests for HMAC generation and verification."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.key = generate_hmac_key()
        self.message = b"Test message for HMAC"
    
    def test_hmac_length(self):
        """Test that HMAC output is correct length (32 bytes for SHA256)."""
        hmac = generate_hmac(self.message, self.key)
        self.assertEqual(len(hmac), 32)
    
    def test_hmac_deterministic(self):
        """Test that same message and key produce same HMAC."""
        # LEARN: HMAC must be deterministic for verification to work
        hmac1 = generate_hmac(self.message, self.key)
        hmac2 = generate_hmac(self.message, self.key)
        self.assertEqual(hmac1, hmac2)
    
    def test_hmac_different_messages(self):
        """Test that different messages produce different HMACs."""
        hmac1 = generate_hmac(b"Message 1", self.key)
        hmac2 = generate_hmac(b"Message 2", self.key)
        self.assertNotEqual(hmac1, hmac2)
    
    def test_hmac_different_keys(self):
        """Test that different keys produce different HMACs."""
        key2 = generate_hmac_key()
        hmac1 = generate_hmac(self.message, self.key)
        hmac2 = generate_hmac(self.message, key2)
        self.assertNotEqual(hmac1, hmac2)
    
    def test_hmac_verification_success(self):
        """Test successful HMAC verification."""
        hmac = generate_hmac(self.message, self.key)
        self.assertTrue(verify_hmac(self.message, hmac, self.key))
    
    def test_hmac_verification_failure_wrong_key(self):
        """Test HMAC verification fails with wrong key."""
        wrong_key = generate_hmac_key()
        hmac = generate_hmac(self.message, self.key)
        self.assertFalse(verify_hmac(self.message, hmac, wrong_key))
    
    def test_hmac_verification_failure_tampered_message(self):
        """Test HMAC verification fails when message is tampered."""
        hmac = generate_hmac(self.message, self.key)
        tampered_message = b"Tampered message"
        
        # LEARN: This is the key security property - tampering is detected
        self.assertFalse(verify_hmac(tampered_message, hmac, self.key))


class TestHMACString(unittest.TestCase):
    """Tests for string-based HMAC functions."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.key = generate_hmac_key()
        self.message = "Test string message"
    
    def test_string_hmac_roundtrip(self):
        """Test string HMAC generation and verification."""
        hmac = generate_hmac_string(self.message, self.key)
        self.assertTrue(verify_hmac_string(self.message, hmac, self.key))
    
    def test_string_hmac_is_base64(self):
        """Test that string HMAC is valid Base64."""
        import base64
        hmac = generate_hmac_string(self.message, self.key)
        # Should not raise exception
        base64.b64decode(hmac)


class TestHashing(unittest.TestCase):
    """Tests for hash functions."""
    
    def test_sha256_length(self):
        """Test SHA256 output length."""
        hash_bytes = hash_sha256(b"Test")
        self.assertEqual(len(hash_bytes), 32)  # 256 bits
    
    def test_sha256_deterministic(self):
        """Test SHA256 produces same output for same input."""
        hash1 = hash_sha256(b"Same data")
        hash2 = hash_sha256(b"Same data")
        self.assertEqual(hash1, hash2)
    
    def test_sha256_different_inputs(self):
        """Test SHA256 produces different output for different inputs."""
        hash1 = hash_sha256(b"Data 1")
        hash2 = hash_sha256(b"Data 2")
        self.assertNotEqual(hash1, hash2)
    
    def test_sha256_avalanche(self):
        """Test avalanche effect - small change produces very different hash."""
        # LEARN: The avalanche effect is a key property of secure hash functions
        hash1 = hash_sha256(b"Hello")
        hash2 = hash_sha256(b"hello")  # Just changed case
        
        # Count differing bits
        differing_bits = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(hash1, hash2))
        
        # LEARN: Good hash should have ~50% of bits different
        # At least 25% should differ
        self.assertGreater(differing_bits, 64)  # 64/256 = 25%
    
    def test_hash_string(self):
        """Test string hash function."""
        hex_hash = hash_sha256_string("Test")
        self.assertEqual(len(hex_hash), 64)  # 64 hex chars = 256 bits


class TestNonce(unittest.TestCase):
    """Tests for nonce generation and replay prevention."""
    
    def setUp(self):
        """Clear nonce cache before each test."""
        clear_nonce_cache()
    
    def test_nonce_length(self):
        """Test nonce is correct length."""
        nonce = generate_nonce()
        self.assertEqual(len(nonce), NONCE_SIZE)
    
    def test_nonce_uniqueness(self):
        """Test nonces are unique."""
        nonces = [generate_nonce_string() for _ in range(100)]
        self.assertEqual(len(nonces), len(set(nonces)))
    
    def test_nonce_replay_prevention(self):
        """Test that nonces can only be used once."""
        nonce = generate_nonce_string()
        
        # First use should succeed
        self.assertTrue(check_and_record_nonce(nonce))
        
        # LEARN: Second use should fail - this prevents replay attacks
        self.assertFalse(check_and_record_nonce(nonce))
    
    def test_different_nonces_accepted(self):
        """Test that different nonces are all accepted."""
        for _ in range(10):
            nonce = generate_nonce_string()
            self.assertTrue(check_and_record_nonce(nonce))


class TestTimestamp(unittest.TestCase):
    """Tests for timestamp validation."""
    
    def test_current_timestamp_valid(self):
        """Test that current timestamp is valid."""
        timestamp = create_timestamp()
        is_valid, _ = verify_timestamp(timestamp)
        self.assertTrue(is_valid)
    
    def test_old_timestamp_invalid(self):
        """Test that old timestamp is rejected."""
        # Create timestamp from 10 minutes ago
        old_timestamp = create_timestamp() - 600
        is_valid, error = verify_timestamp(old_timestamp, max_age=300)
        
        self.assertFalse(is_valid)
        self.assertIn("too old", error)
    
    def test_future_timestamp_invalid(self):
        """Test that future timestamp is rejected."""
        # Create timestamp 5 minutes in future
        future_timestamp = create_timestamp() + 300
        is_valid, error = verify_timestamp(future_timestamp)
        
        self.assertFalse(is_valid)
        self.assertIn("future", error)


class TestIntegrityData(unittest.TestCase):
    """Tests for combined integrity data functions."""
    
    def setUp(self):
        """Set up test fixtures."""
        clear_nonce_cache()
        self.hmac_key = generate_hmac_key()
        self.message = "Test message"
    
    def test_create_integrity_data(self):
        """Test integrity data creation."""
        data = create_integrity_data(self.message, self.hmac_key)
        
        self.assertIn('hmac', data)
        self.assertIn('nonce', data)
        self.assertIn('timestamp', data)
    
    def test_verify_integrity_data_success(self):
        """Test successful integrity verification."""
        data = create_integrity_data(self.message, self.hmac_key)
        is_valid, _ = verify_integrity_data(self.message, data, self.hmac_key)
        
        self.assertTrue(is_valid)
    
    def test_verify_integrity_data_tampered(self):
        """Test that tampered message is detected."""
        data = create_integrity_data(self.message, self.hmac_key)
        
        tampered_message = "Tampered message"
        is_valid, error = verify_integrity_data(tampered_message, data, self.hmac_key)
        
        self.assertFalse(is_valid)
        self.assertIn("tampered", error)


class TestPasswordHashing(unittest.TestCase):
    """Tests for password hashing functions."""
    
    def test_password_hash_verify_success(self):
        """Test successful password verification."""
        password = "SecurePassword123!"
        
        hashed, salt = hash_password(password)
        self.assertTrue(verify_password(password, hashed, salt))
    
    def test_password_hash_verify_failure(self):
        """Test that wrong password fails verification."""
        password = "SecurePassword123!"
        wrong_password = "WrongPassword456!"
        
        hashed, salt = hash_password(password)
        self.assertFalse(verify_password(wrong_password, hashed, salt))
    
    def test_password_hash_unique_salts(self):
        """Test that same password gets different hashes with different salts."""
        password = "SamePassword"
        
        hash1, salt1 = hash_password(password)
        hash2, salt2 = hash_password(password)
        
        # LEARN: Different salts mean different hashes, even for same password
        self.assertNotEqual(hash1, hash2)
        self.assertNotEqual(salt1, salt2)


if __name__ == '__main__':
    unittest.main()
