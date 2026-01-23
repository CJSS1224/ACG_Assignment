"""
Authentication Service

Handles user authentication including password hashing,
JWT token generation and verification.
"""

import os
import bcrypt
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify
from dotenv import load_dotenv

load_dotenv()

# Configuration
JWT_SECRET = os.getenv('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_EXPIRES_IN = int(os.getenv('JWT_EXPIRES_IN', 86400))  # 24 hours default


def hash_password(password):
    """
    Hash a password using bcrypt.
    
    Args:
        password: Plain text password
        
    Returns:
        Hashed password string
    """
    salt = bcrypt.gensalt(rounds=10)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def verify_password(password, password_hash):
    """
    Verify a password against its hash.
    
    Args:
        password: Plain text password
        password_hash: Stored hash
        
    Returns:
        True if password matches, False otherwise
    """
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))


def generate_token(user_id, username):
    """
    Generate a JWT token for a user.
    
    Args:
        user_id: User ID
        username: Username
        
    Returns:
        JWT token string
    """
    payload = {
        'id': user_id,
        'username': username,
        'exp': datetime.utcnow() + timedelta(seconds=JWT_EXPIRES_IN),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')


def verify_token(token):
    """
    Verify and decode a JWT token.
    
    Args:
        token: JWT token string
        
    Returns:
        Decoded payload or None if invalid
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def token_required(f):
    """
    Decorator to require valid JWT token for a route.
    
    Usage:
        @app.route('/protected')
        @token_required
        def protected_route():
            # request.user contains the decoded token payload
            pass
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': 'Access denied. No token provided.'}), 401
        
        # Verify token
        payload = verify_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token.'}), 403
        
        # Attach user info to request
        request.user = payload
        
        return f(*args, **kwargs)
    
    return decorated


def get_token_from_request():
    """
    Extract JWT token from request header or query parameter.
    
    Returns:
        Token string or None
    """
    # Try Authorization header first
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        return auth_header.split(' ')[1]
    
    # Try query parameter (for WebSocket)
    token = request.args.get('token')
    if token:
        return token
    
    return None
