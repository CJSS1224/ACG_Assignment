"""
HTTP Routes - ST2504 Applied Cryptography
==========================================

All REST API endpoints:
- Authentication routes (Solomon)
- Chat routes (Charles)
"""

from flask import Blueprint, request, jsonify
from models.auth_model import AuthModel, token_required
from models.crypto_model import CryptoModel
from models.database_model import DatabaseModel

# Initialize
api = Blueprint('api', __name__)
auth = AuthModel()
crypto = CryptoModel()
db = DatabaseModel()


# ==================== AUTH ROUTES (Solomon) ====================

@api.route('/register', methods=['POST'])
def register():
    """Register a new user."""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    # Validate
    if len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    
    # Check if exists
    if db.get_user_by_username(username):
        return jsonify({'error': 'Username already exists'}), 400
    
    # Generate RSA keypair (Denise)
    private_key, public_key = crypto.generate_rsa_keypair()
    
    # Encrypt private key with password (Denise)
    encrypted = crypto.encrypt_private_key(private_key, password)
    
    # Hash password (Solomon)
    password_hash = auth.hash_password(password)
    
    # Create user (Akash)
    user_id = db.create_user(
        username=username,
        password_hash=password_hash,
        public_key=public_key,
        encrypted_private_key=encrypted['encrypted_private_key'],
        private_key_iv=encrypted['iv'],
        private_key_salt=encrypted['salt']
    )
    
    # Generate token
    token = auth.generate_token(user_id, username)
    
    return jsonify({
        'token': token,
        'user': {'id': user_id, 'username': username, 'public_key': public_key},
        'private_key': private_key
    }), 201


@api.route('/login', methods=['POST'])
def login():
    """Login user."""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    # Get user
    user = db.get_user_by_username(username)
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Verify password (Solomon)
    if not auth.verify_password(password, user['password_hash']):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Decrypt private key (Denise)
    try:
        private_key = crypto.decrypt_private_key(
            user['encrypted_private_key'],
            user['private_key_iv'],
            user['private_key_salt'],
            password
        )
    except:
        return jsonify({'error': 'Failed to decrypt private key'}), 500
    
    # Generate token
    token = auth.generate_token(user['id'], user['username'])
    
    return jsonify({
        'token': token,
        'user': {'id': user['id'], 'username': user['username'], 'public_key': user['public_key']},
        'private_key': private_key
    })


@api.route('/me', methods=['GET'])
@token_required
def get_me(current_user):
    """Get current user info."""
    user = db.get_user_by_id(current_user['id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'id': user['id'], 'username': user['username'], 'public_key': user['public_key']})


# ==================== CHAT ROUTES (Charles) ====================

@api.route('/chats', methods=['GET'])
@token_required
def get_chats(current_user):
    """Get user's chats."""
    chats = db.get_user_chats(current_user['id'])
    return jsonify(chats)


@api.route('/chats', methods=['POST'])
@token_required
def create_chat(current_user):
    """Create or get existing chat."""
    data = request.get_json()
    other_user_id = data.get('user_id')
    
    if not other_user_id:
        return jsonify({'error': 'user_id required'}), 400
    
    other_user = db.get_user_by_id(other_user_id)
    if not other_user:
        return jsonify({'error': 'User not found'}), 404
    
    chat_id = db.get_or_create_chat(current_user['id'], other_user_id)
    
    return jsonify({
        'chat_id': chat_id,
        'other_user': {
            'id': other_user['id'],
            'username': other_user['username'],
            'public_key': other_user['public_key']
        }
    })


@api.route('/chats/<int:other_user_id>/messages', methods=['GET'])
@token_required
def get_messages(current_user, other_user_id):
    """Get messages for a chat."""
    messages = db.get_chat_messages(current_user['id'], other_user_id)
    return jsonify(messages)
