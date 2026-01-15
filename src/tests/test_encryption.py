"""
Encryption Tests - Member 3: [Name]

Unit tests for the encryption module to verify:
- AES key generation
- Encryption and decryption
- Padding operations
- Error handling

Run with: python -m pytest src/tests/test_encryption.py -v
"""

import unittest
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.crypto.encryption import (
    generate_aes_key,
    generate_iv,
    pad_data,
    unpad_data,
    encrypt_message,
    decrypt_message,
    encrypt_message_bundled,
    decrypt_message_bundled,
    encrypt_for_storage,
    decrypt_from_storage,
    AES_KEY_SIZE,
    AES_BLOCK_SIZE
)
from src.utils.constants import AES_KEY_SIZE, AES_BLOCK_SIZE


class TestKeyGeneration(unittest.TestCase):
    """Tests for AES key generation."""
    
    def test_key_length(self):
        """Test that generated key is correct length (32 bytes)."""
        key = generate_aes_key()
        self.assertEqual(len(key), AES_KEY_SIZE)
        self.assertEqual(len(key), 32)  # 256 bits
    
    def test_key_randomness(self):
        """Test that each generated key is unique."""
        # LEARN: This tests that the random generator is working
        # LEARN: Two calls should produce different keys
        key1 = generate_aes_key()
        key2 = generate_aes_key()
        self.assertNotEqual(key1, key2)
    
    def test_iv_length(self):
        """Test that generated IV is correct length (16 bytes)."""
        iv = generate_iv()
        self.assertEqual(len(iv), AES_BLOCK_SIZE)
        self.assertEqual(len(iv), 16)  # 128 bits
    
    def test_iv_randomness(self):
        """Test that each generated IV is unique."""
        iv1 = generate_iv()
        iv2 = generate_iv()
        self.assertNotEqual(iv1, iv2)


class TestPadding(unittest.TestCase):
    """Tests for PKCS7 padding operations."""
    
    def test_padding_short_data(self):
        """Test padding data shorter than block size."""
        data = b"Hello"  # 5 bytes
        padded = pad_data(data)
        
        # Should be padded to 16 bytes
        self.assertEqual(len(padded) % AES_BLOCK_SIZE, 0)
        self.assertEqual(len(padded), 16)
    
    def test_padding_exact_block(self):
        """Test padding data exactly one block size."""
        data = b"0123456789ABCDEF"  # 16 bytes
        padded = pad_data(data)
        
        # LEARN: When data is exactly block size, a full block of padding is added
        # LEARN: This ensures unambiguous unpadding
        self.assertEqual(len(padded), 32)
    
    def test_unpadding(self):
        """Test that padding can be removed correctly."""
        original = b"Test message"
        padded = pad_data(original)
        unpadded = unpad_data(padded)
        
        self.assertEqual(original, unpadded)
    
    def test_unpadding_all_lengths(self):
        """Test padding/unpadding for various data lengths."""
        for length in range(1, 50):
            original = os.urandom(length)
            padded = pad_data(original)
            unpadded = unpad_data(padded)
            self.assertEqual(original, unpadded, f"Failed for length {length}")


class TestEncryptDecrypt(unittest.TestCase):
    """Tests for message encryption and decryption."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.key = generate_aes_key()
        self.test_messages = [
            "Hello, World!",
            "Short",
            "A" * 1000,  # Long message
            "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?",
            "Unicode: 你好世界 🌍 مرحبا",
            "",  # Empty message
        ]
    
    def test_encrypt_decrypt_basic(self):
        """Test basic encryption and decryption."""
        plaintext = "Hello, World!"
        
        ciphertext, iv = encrypt_message(plaintext, self.key)
        decrypted = decrypt_message(ciphertext, iv, self.key)
        
        self.assertEqual(plaintext, decrypted)
    
    def test_encrypt_decrypt_various_messages(self):
        """Test encryption/decryption with various message types."""
        for plaintext in self.test_messages:
            with self.subTest(msg=plaintext[:20]):
                ciphertext, iv = encrypt_message(plaintext, self.key)
                decrypted = decrypt_message(ciphertext, iv, self.key)
                self.assertEqual(plaintext, decrypted)
    
    def test_ciphertext_is_different(self):
        """Test that ciphertext differs from plaintext."""
        plaintext = "Secret message"
        ciphertext, iv = encrypt_message(plaintext, self.key)
        
        # LEARN: Ciphertext should look nothing like plaintext
        self.assertNotEqual(plaintext, ciphertext)
        self.assertNotIn("Secret", ciphertext)
    
    def test_different_ivs_produce_different_ciphertext(self):
        """Test that same plaintext with different IVs produces different ciphertext."""
        plaintext = "Same message"
        
        ct1, iv1 = encrypt_message(plaintext, self.key)
        ct2, iv2 = encrypt_message(plaintext, self.key)
        
        # LEARN: Random IV ensures same message encrypts differently each time
        # LEARN: This is crucial for security
        self.assertNotEqual(ct1, ct2)
        self.assertNotEqual(iv1, iv2)
    
    def test_wrong_key_fails(self):
        """Test that decryption with wrong key fails."""
        plaintext = "Secret message"
        wrong_key = generate_aes_key()
        
        ciphertext, iv = encrypt_message(plaintext, self.key)
        
        # LEARN: Wrong key should cause decryption to fail
        # LEARN: Usually results in padding error or garbage output
        with self.assertRaises(Exception):
            decrypt_message(ciphertext, iv, wrong_key)


class TestBundledEncryption(unittest.TestCase):
    """Tests for bundled IV encryption."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.key = generate_aes_key()
    
    def test_bundled_encrypt_decrypt(self):
        """Test bundled encryption and decryption."""
        plaintext = "Test message for bundled encryption"
        
        bundled = encrypt_message_bundled(plaintext, self.key)
        decrypted = decrypt_message_bundled(bundled, self.key)
        
        self.assertEqual(plaintext, decrypted)
    
    def test_bundled_single_output(self):
        """Test that bundled encryption returns single string."""
        plaintext = "Test"
        bundled = encrypt_message_bundled(plaintext, self.key)
        
        # Should be a single Base64 string
        self.assertIsInstance(bundled, str)


class TestStorageEncryption(unittest.TestCase):
    """Tests for at-rest storage encryption."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.key = generate_aes_key()
    
    def test_storage_encrypt_decrypt(self):
        """Test storage encryption and decryption."""
        plaintext = "Data to store securely"
        
        encrypted = encrypt_for_storage(plaintext, self.key)
        decrypted = decrypt_from_storage(encrypted, self.key)
        
        self.assertEqual(plaintext, decrypted)
    
    def test_storage_format(self):
        """Test that storage format contains expected fields."""
        plaintext = "Test"
        encrypted = encrypt_for_storage(plaintext, self.key)
        
        # LEARN: Storage format should be self-documenting
        self.assertIn('ciphertext', encrypted)
        self.assertIn('iv', encrypted)
        self.assertIn('algorithm', encrypted)
        self.assertEqual(encrypted['algorithm'], 'AES-256-CBC')


if __name__ == '__main__':
    unittest.main()
