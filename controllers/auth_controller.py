"""
Authentication Controller - ST2504 Applied Cryptography

This controller handles authentication business logic:
- User registration (Solomon)
- User login (Solomon)
- Token validation (Solomon)
- Private key encryption/decryption (Denise)

Uses AuthModel and CryptoModel for operations.
"""

from models.auth_model import AuthModel
from models.crypto_model import CryptoModel
from models.database_model import DatabaseModel


class AuthController:
    """Controller for authentication operations."""
    
    def __init__(self):
        self.auth = AuthModel()
        self.crypto = CryptoModel()
        self.db = DatabaseModel()
    
    def register(self, username: str, password: str) -> tuple:
        """
        Register a new user.
        - Generates RSA keypair
        - Encrypts private key with password
        - Stores encrypted private key in database
        
        Returns:
            tuple of (dict, status_code)
        """
        # Validate input
        if not username or len(username) < 3:
            return {'error': 'Username must be at least 3 characters'}, 400
        if not password or len(password) < 6:
            return {'error': 'Password must be at least 6 characters'}, 400
        
        # Check if username exists
        if self.db.get_user_by_username(username):
            return {'error': 'Username already exists'}, 400
        
        # Generate RSA keypair (Denise)
        private_key_pem, public_key_pem = self.crypto.generate_rsa_keypair()
        
        # Encrypt private key with password (Denise)
        encrypted_key_data = self.crypto.encrypt_private_key(private_key_pem, password)
        
        # Hash password and create user (Solomon)
        password_hash = self.auth.hash_password(password)
        user_id = self.db.create_user(
            username=username,
            password_hash=password_hash,
            public_key=public_key_pem,
            encrypted_private_key=encrypted_key_data['encrypted_private_key'],
            private_key_iv=encrypted_key_data['iv'],
            private_key_salt=encrypted_key_data['salt']
        )
        
        if not user_id:
            return {'error': 'Failed to create user'}, 500
        
        # Generate token (Solomon)
        token = self.auth.generate_token(user_id, username)
        
        return {
            'token': token,
            'user_id': user_id,
            'username': username,
            'public_key': public_key_pem,
            'private_key': private_key_pem  # Return for client storage
        }, 201
    
    def login(self, username: str, password: str) -> tuple:
        """
        Authenticate a user.
        - Verifies password
        - Decrypts and returns private key
        
        Returns:
            tuple of (dict, status_code)
        """
        if not username or not password:
            return {'error': 'Username and password required'}, 400
        
        # Get user from database
        user = self.db.get_user_by_username(username)
        if not user:
            return {'error': 'Invalid username or password'}, 401
        
        # Verify password (Solomon)
        if not self.auth.verify_password(password, user['password_hash']):
            return {'error': 'Invalid username or password'}, 401
        
        # Decrypt private key (Denise)
        private_key = None
        try:
            if user.get('encrypted_private_key') and user.get('private_key_iv') and user.get('private_key_salt'):
                private_key = self.crypto.decrypt_private_key(
                    encrypted_private_key=user['encrypted_private_key'],
                    iv=user['private_key_iv'],
                    salt=user['private_key_salt'],
                    password=password
                )
        except Exception as e:
            print(f"[AUTH] Failed to decrypt private key: {e}")
            return {'error': 'Failed to decrypt private key'}, 500
        
        # Update last login
        self.db.update_last_login(user['id'])
        
        # Generate token (Solomon)
        token = self.auth.generate_token(user['id'], user['username'])
        
        return {
            'token': token,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'public_key': user['public_key']
            },
            'private_key': private_key  # Return decrypted private key
        }, 200
    
    def get_current_user(self, user_id: int) -> tuple:
        """
        Get current user info.
        
        Returns:
            tuple of (dict, status_code)
        """
        user = self.db.get_user_by_id(user_id)
        if not user:
            return {'error': 'User not found'}, 404
        
        return {
            'id': user['id'],
            'username': user['username'],
            'public_key': user['public_key']
        }, 200
