"""
User Service
============
Implemented by: Akash (User Authentication & Database Specialist)

Handles user registration, login, and key management.

Functions:
    - register_user: Create new account with RSA keypair
    - login_user: Authenticate and return decrypted private key
    - get_user: Get user info by ID
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bcrypt
from typing import Optional
from crypto import (
    generate_rsa_keypair,
    encrypt_private_key,
    decrypt_private_key,
    generate_session_secret
)
from models.database import Database


class UserService:
    """Handles user authentication and key management. [Akash]"""
    
    def __init__(self, db: Database):
        """Initialize with database connection."""
        self.db = db
    
    def register_user(self, username: str, password: str) -> dict:
        """
        Register a new user. [Akash]
        
        Process:
            1. Validate input [Akash]
            2. Check username availability [Akash]
            3. Hash password with bcrypt [Akash]
            4. Generate RSA-2048 keypair [Uses Amir's generate_rsa_keypair]
            5. Encrypt private key with password-derived key [Uses Denise's encrypt_private_key]
            6. Store in database [Akash]
        
        Args:
            username: Desired username (3+ chars)
            password: Password (6+ chars)
            
        Returns:
            dict: {
                'success': bool,
                'error': str (if failed),
                'user': dict (if success),
                'private_key': str (if success)
            }
        """
        # =================================================================
        # STEP 1: Validate input
        # =================================================================
        if len(username) < 3:
            return {'success': False, 'error': 'Username must be at least 3 characters'}
        if len(password) < 6:
            return {'success': False, 'error': 'Password must be at least 6 characters'}
        
        # =================================================================
        # STEP 2: Check username availability
        # =================================================================
        existing = self.db.get_user_by_username(username)
        if existing:
            return {'success': False, 'error': 'Username already taken'}
        
        # =================================================================
        # STEP 3: Hash password with bcrypt [Akash]
        # =================================================================
        password_hash = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt(rounds=12)
        ).decode('utf-8')
        
        # =================================================================
        # STEP 4: Generate RSA-2048 keypair [Uses Amir's generate_rsa_keypair]
        # =================================================================
        private_key_pem, public_key_pem = generate_rsa_keypair()
        
        # =================================================================
        # STEP 5: Encrypt private key with password-derived key
        #         [Uses Denise's encrypt_private_key → PBKDF2 + AES-GCM]
        # =================================================================
        encrypted = encrypt_private_key(private_key_pem, password)
        
        # =================================================================
        # STEP 6: Store in database [Akash's Database.create_user]
        # =================================================================
        user_id = self.db.create_user(
            username=username,
            password_hash=password_hash,
            public_key=public_key_pem,
            encrypted_private_key=encrypted['encrypted_private_key'],
            nonce=encrypted['nonce'],
            tag=encrypted['tag'],
            salt=encrypted['salt']
        )
        
        if not user_id:
            return {'success': False, 'error': 'Failed to create user'}
        
        return {
            'success': True,
            'user': {
                'id': user_id,
                'username': username,
                'public_key': public_key_pem
            },
            'private_key': private_key_pem
        }
    
    def login_user(self, username: str, password: str) -> dict:
        """
        Authenticate a user. [Akash]
        
        Process:
            1. Find user by username [Akash]
            2. Verify password with bcrypt [Akash]
            3. Decrypt private key using password [Uses Denise's decrypt_private_key]
            4. Generate session secret for HMAC [Uses Denise's generate_session_secret]
        
        Args:
            username: Username
            password: Password
            
        Returns:
            dict: {
                'success': bool,
                'error': str (if failed),
                'user': dict (if success),
                'private_key': str (if success),
                'session_secret': bytes (if success)
            }
        """
        # =================================================================
        # STEP 1: Find user by username
        # =================================================================
        user = self.db.get_user_by_username(username)
        if not user:
            return {'success': False, 'error': 'Invalid username or password'}
        
        # =================================================================
        # STEP 2: Verify password with bcrypt
        # =================================================================
        if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            return {'success': False, 'error': 'Invalid username or password'}
        
        # =================================================================
        # STEP 3: Decrypt private key using password
        #         [Uses Denise's decrypt_private_key → PBKDF2 + AES-GCM]
        # =================================================================
        try:
            private_key = decrypt_private_key(
                {
                    'encrypted_private_key': user['encrypted_private_key'],
                    'nonce': user['private_key_nonce'],
                    'tag': user['private_key_tag'],
                    'salt': user['private_key_salt']
                },
                password
            )
        except Exception as e:
            return {'success': False, 'error': 'Failed to decrypt private key'}
        
        # =================================================================
        # STEP 4: Generate session secret for HMAC [Uses Denise's generate_session_secret]
        # =================================================================
        session_secret = generate_session_secret()
        
        return {
            'success': True,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'public_key': user['public_key']
            },
            'private_key': private_key,
            'session_secret': session_secret
        }
    
    def get_user(self, user_id: int) -> Optional[dict]:
        """Get user by ID (public info only). [Akash]"""
        return self.db.get_user_by_id(user_id)
    
    def get_all_users(self, exclude_id: int = None) -> list:
        """Get all users (for user list). [Akash]"""
        return self.db.get_all_users(exclude_id)
