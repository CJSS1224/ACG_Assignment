"""
Authentication Middleware - ST2504 Applied Cryptography

This middleware handles:
- JWT token validation (Solomon)
- Request authentication
- Token extraction from headers

Used by routes that require authentication.
"""

from functools import wraps
from flask import request, jsonify
from models.auth_model import AuthModel


# Initialize auth model
auth_model = AuthModel()


def token_required(f):
    """
    Decorator to protect routes that require authentication.
    Extracts and validates JWT token from Authorization header.
    
    Usage:
        @token_required
        def protected_route(current_user):
            # current_user contains the decoded token payload
            pass
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        payload = auth_model.verify_token(token)
        if not payload:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(payload, *args, **kwargs)
    
    return decorated


def get_token_payload(token: str) -> dict:
    """
    Validate token and return payload.
    Returns None if token is invalid.
    """
    return auth_model.verify_token(token)
