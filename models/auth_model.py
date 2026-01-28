"""
Authentication Model - ST2504 Applied Cryptography
===================================================

Handles authentication:
- Password hashing with bcrypt (Solomon)
- JWT token management (Solomon)
"""

import os
import bcrypt
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify
from dotenv import load_dotenv

load_dotenv()

JWT_SECRET = os.getenv('JWT_SECRET', 'your-secret-key')
JWT_EXPIRY_HOURS = 24


class AuthModel:
    """Password hashing and JWT tokens."""
    
    # ==================== PASSWORD HASHING (Solomon) ====================
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt (12 rounds)."""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash."""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except:
            return False
    
    # ==================== JWT TOKEN MANAGEMENT (Solomon) ====================
    
    def generate_token(self, user_id: int, username: str) -> str:
        """Generate JWT token (24 hour expiry)."""
        payload = {
            'id': user_id,
            'username': username,
            'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    
    def verify_token(self, token: str) -> dict:
        """Verify and decode JWT token."""
        try:
            return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        except:
            return None


# ==================== AUTH DECORATOR ====================

auth_model = AuthModel()

def token_required(f):
    """Decorator to require valid JWT token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Token missing'}), 401
        
        payload = auth_model.verify_token(token)
        if not payload:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(payload, *args, **kwargs)
    return decorated
