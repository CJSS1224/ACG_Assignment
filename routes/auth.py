"""
Authentication Routes
=====================
Handles user registration and login.

Endpoints:
    POST /api/register - Create new account
    POST /api/login - Authenticate user
    GET /api/me - Get current user info
"""

import jwt
import base64
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, current_app
from functools import wraps

from models import Database, UserService


# Create blueprint
auth_bp = Blueprint('auth', __name__)

# Initialize services (will be set up in app.py)
db = None
user_service = None


def init_auth(database: Database):
    """Initialize auth routes with database."""
    global db, user_service
    db = database
    user_service = UserService(db)


def create_token(user_id: int, session_secret: bytes) -> str:
    """Create JWT token with user ID and session secret."""
    payload = {
        'user_id': user_id,
        'session_secret': base64.b64encode(session_secret).decode('utf-8'),
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')


def token_required(f):
    """Decorator to require valid JWT token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': 'Token required'}), 401
        
        try:
            payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            request.user_id = payload['user_id']
            request.session_secret = base64.b64decode(payload['session_secret'])
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    
    return decorated


# =============================================================================
# ROUTES
# =============================================================================

@auth_bp.route('/api/register', methods=['POST'])
def register():
    """
    Register a new user.
    
    Request body:
        {
            "username": "alice",
            "password": "secret123"
        }
    
    Response:
        {
            "token": "jwt_token",
            "user": {"id": 1, "username": "alice", "public_key": "..."},
            "private_key": "-----BEGIN PRIVATE KEY-----...",
            "session_secret": "base64_encoded_secret"
        }
    """
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password required'}), 400
    
    result = user_service.register_user(data['username'], data['password'])
    
    if not result['success']:
        return jsonify({'error': result['error']}), 400
    
    # Generate session secret
    from crypto import generate_session_secret
    session_secret = generate_session_secret()
    
    # Create token
    token = create_token(result['user']['id'], session_secret)
    
    return jsonify({
        'token': token,
        'user': result['user'],
        'private_key': result['private_key'],
        'session_secret': base64.b64encode(session_secret).decode('utf-8')
    })


@auth_bp.route('/api/login', methods=['POST'])
def login():
    """
    Login user.
    
    Request body:
        {
            "username": "alice",
            "password": "secret123"
        }
    
    Response:
        {
            "token": "jwt_token",
            "user": {"id": 1, "username": "alice", "public_key": "..."},
            "private_key": "-----BEGIN PRIVATE KEY-----...",
            "session_secret": "base64_encoded_secret"
        }
    """
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password required'}), 400
    
    result = user_service.login_user(data['username'], data['password'])
    
    if not result['success']:
        return jsonify({'error': result['error']}), 401
    
    # Create token
    token = create_token(result['user']['id'], result['session_secret'])
    
    return jsonify({
        'token': token,
        'user': result['user'],
        'private_key': result['private_key'],
        'session_secret': base64.b64encode(result['session_secret']).decode('utf-8')
    })


@auth_bp.route('/api/me', methods=['GET'])
@token_required
def get_current_user():
    """Get current user info."""
    user = user_service.get_user(request.user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({'user': user})
