"""
Authentication Service - ST2504 Applied Cryptography

This module handles user authentication:
- Password hashing with bcrypt (Member 1)
- JWT token generation and verification (Member 1)

Security Features:
- Passwords are never stored in plaintext
- bcrypt provides salting and adaptive hashing
- JWT tokens expire after 24 hours
"""

import os
import bcrypt
import jwt
from datetime import datetime, timedelta
from typing import Optional
from dotenv import load_dotenv

load_dotenv()


class AuthService:
    """
    Authentication service providing:
    - Secure password hashing with bcrypt
    - JWT token generation and verification
    """
    
    # JWT configuration
    JWT_SECRET = os.getenv('JWT_SECRET', 'your-secret-key-change-in-production')
    JWT_ALGORITHM = 'HS256'
    JWT_EXPIRY_HOURS = 24
    
    # bcrypt configuration
    BCRYPT_ROUNDS = 12  # Cost factor (higher = slower but more secure)
    
    def __init__(self, db_service=None):
        """
        Initialize auth service.
        
        Args:
            db_service: Database service instance (optional)
        """
        self.db = db_service
    
    # ==========================================================================
    # PASSWORD HASHING - Member 1
    # ==========================================================================
    
    def hash_password(self, password: str) -> str:
        """
        Hash a password using bcrypt.
        
        bcrypt automatically:
        - Generates a random salt
        - Includes the salt in the hash
        - Uses adaptive cost factor
        
        Args:
            password: Plain text password
            
        Returns:
            bcrypt hash string (includes salt)
        """
        # Convert to bytes and hash
        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt(rounds=self.BCRYPT_ROUNDS)
        hashed = bcrypt.hashpw(password_bytes, salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """
        Verify a password against its hash.
        
        bcrypt automatically extracts the salt from the hash
        and performs constant-time comparison.
        
        Args:
            password: Plain text password to verify
            password_hash: Stored bcrypt hash
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            password_bytes = password.encode('utf-8')
            hash_bytes = password_hash.encode('utf-8')
            return bcrypt.checkpw(password_bytes, hash_bytes)
        except Exception:
            return False
    
    # ==========================================================================
    # JWT TOKEN MANAGEMENT - Member 1
    # ==========================================================================
    
    def generate_token(self, user_id: int, username: str) -> str:
        """
        Generate a JWT token for authenticated user.
        
        JWT (JSON Web Token) contains:
        - User ID and username (payload)
        - Expiration time
        - Signature to prevent tampering
        
        Args:
            user_id: User's database ID
            username: User's username
            
        Returns:
            JWT token string
        """
        payload = {
            'id': user_id,
            'username': username,
            'exp': datetime.utcnow() + timedelta(hours=self.JWT_EXPIRY_HOURS),
            'iat': datetime.utcnow()  # Issued at
        }
        
        token = jwt.encode(payload, self.JWT_SECRET, algorithm=self.JWT_ALGORITHM)
        return token
    
    def verify_token(self, token: str) -> Optional[dict]:
        """
        Verify and decode a JWT token.
        
        Checks:
        - Token signature is valid
        - Token has not expired
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded payload dict if valid, None if invalid
        """
        try:
            payload = jwt.decode(
                token, 
                self.JWT_SECRET, 
                algorithms=[self.JWT_ALGORITHM]
            )
            return payload
        except jwt.ExpiredSignatureError:
            print("[AUTH] Token expired")
            return None
        except jwt.InvalidTokenError as e:
            print(f"[AUTH] Invalid token: {e}")
            return None
