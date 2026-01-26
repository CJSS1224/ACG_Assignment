"""
Authentication Model - ST2504 Applied Cryptography

This model handles user authentication:
- Password hashing with bcrypt (Solomon)
- JWT token generation and verification (Solomon)

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


class AuthModel:
    """
    Authentication model providing:
    - Secure password hashing with bcrypt
    - JWT token generation and verification
    """
    
    # JWT configuration
    JWT_SECRET = os.getenv('JWT_SECRET', 'your-secret-key-change-in-production')
    JWT_ALGORITHM = 'HS256'
    JWT_EXPIRY_HOURS = 24
    
    # bcrypt configuration
    BCRYPT_ROUNDS = 12  # Cost factor
    
    # ==========================================================================
    # PASSWORD HASHING - Solomon
    # ==========================================================================
    
    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt."""
        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt(rounds=self.BCRYPT_ROUNDS)
        hashed = bcrypt.hashpw(password_bytes, salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify a password against its hash."""
        try:
            password_bytes = password.encode('utf-8')
            hash_bytes = password_hash.encode('utf-8')
            return bcrypt.checkpw(password_bytes, hash_bytes)
        except Exception:
            return False
    
    # ==========================================================================
    # JWT TOKEN MANAGEMENT - Solomon
    # ==========================================================================
    
    def generate_token(self, user_id: int, username: str) -> str:
        """Generate a JWT token for authenticated user."""
        payload = {
            'id': user_id,
            'username': username,
            'exp': datetime.utcnow() + timedelta(hours=self.JWT_EXPIRY_HOURS),
            'iat': datetime.utcnow()
        }
        
        token = jwt.encode(payload, self.JWT_SECRET, algorithm=self.JWT_ALGORITHM)
        return token
    
    def verify_token(self, token: str) -> Optional[dict]:
        """Verify and decode a JWT token."""
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
