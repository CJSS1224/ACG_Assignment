"""
Authentication Routes

Handles user registration, login, and logout endpoints.
"""

from flask import Blueprint, request, jsonify

from src.models.user_model import (
    create_user, get_user_by_username, get_user_by_id,
    update_last_login, delete_user_sessions
)
from src.services.auth_service import (
    hash_password, verify_password, generate_token, token_required
)
from src.services.crypto_service import generate_user_keypair

# Create blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/api')


@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Register a new user.
    
    Request body:
        - username: string (required)
        - password: string (required)
        
    Returns:
        - user_id, username, public_key on success
        - error message on failure
    """
    data = request.get_json()
    
    # Validate input
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    
    if not password or len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    
    # Check if username exists
    existing_user = get_user_by_username(username)
    if existing_user:
        return jsonify({'error': 'Username already exists'}), 409
    
    # Generate RSA key pair for the user
    private_key_pem, public_key_pem = generate_user_keypair()
    
    # Hash password
    password_hash = hash_password(password)
    
    # Create user
    user_id = create_user(username, password_hash, public_key_pem)
    
    if not user_id:
        return jsonify({'error': 'Failed to create user'}), 500
    
    # Generate JWT token
    token = generate_token(user_id, username)
    
    return jsonify({
        'message': 'Registration successful',
        'user_id': user_id,
        'username': username,
        'token': token,
        'private_key': private_key_pem,
        'public_key': public_key_pem
    }), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Authenticate a user.
    
    Request body:
        - username: string (required)
        - password: string (required)
        
    Returns:
        - token, user info on success
        - error message on failure
    """
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    # Get user from database
    user = get_user_by_username(username)
    
    if not user:
        return jsonify({'error': 'Invalid username or password'}), 401
    
    # Verify password
    if not verify_password(password, user['password_hash']):
        return jsonify({'error': 'Invalid username or password'}), 401
    
    # Update last login
    update_last_login(user['id'])
    
    # Generate JWT token
    token = generate_token(user['id'], user['username'])
    
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'public_key': user['public_key']
        }
    }), 200


@auth_bp.route('/logout', methods=['POST'])
@token_required
def logout():
    """Logout a user (invalidate their session)."""
    from src.socket_handlers.connection_manager import remove_user_session
    
    user_id = request.user['id']
    remove_user_session(user_id)
    
    return jsonify({'message': 'Logout successful'}), 200


@auth_bp.route('/me', methods=['GET'])
@token_required
def get_current_user():
    """Get current user's info."""
    user = get_user_by_id(request.user['id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'public_key': user['public_key']
    }), 200
