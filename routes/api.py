"""
API Routes
==========
REST endpoints for chats and messages.

Endpoints:
    GET /api/users - Get all users
    GET /api/chats - Get user's chats
    GET /api/chats/<user_id>/messages - Get messages with user
"""

from flask import Blueprint, request, jsonify

from models import Database, UserService, MessageService
from routes.auth import token_required


# Create blueprint
api_bp = Blueprint('api', __name__)

# Initialize services (will be set up in app.py)
db = None
user_service = None
message_service = None


def init_api(database: Database):
    """Initialize API routes with database."""
    global db, user_service, message_service
    db = database
    user_service = UserService(db)
    message_service = MessageService(db)


# =============================================================================
# USER ROUTES
# =============================================================================

@api_bp.route('/api/users', methods=['GET'])
@token_required
def get_users():
    """
    Get all users (excluding current user).
    
    Response:
        {
            "users": [
                {"id": 2, "username": "bob", "public_key": "..."},
                ...
            ]
        }
    """
    users = user_service.get_all_users(exclude_id=request.user_id)
    return jsonify({'users': users})


@api_bp.route('/api/users/<int:user_id>', methods=['GET'])
@token_required
def get_user(user_id):
    """Get a specific user."""
    user = user_service.get_user(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({'user': user})


# =============================================================================
# CHAT ROUTES
# =============================================================================

@api_bp.route('/api/chats', methods=['GET'])
@token_required
def get_chats():
    """
    Get all chats for current user.
    
    Response:
        {
            "chats": [
                {
                    "chat_id": 1,
                    "other_user_id": 2,
                    "other_username": "bob",
                    "other_public_key": "...",
                    "last_message_at": "2024-01-29 12:00:00"
                },
                ...
            ]
        }
    """
    chats = db.get_user_chats(request.user_id)
    return jsonify({'chats': chats})


@api_bp.route('/api/chats/<int:other_user_id>/messages', methods=['GET'])
@token_required
def get_messages(other_user_id):
    """
    Get messages between current user and another user.
    
    Requires private_key in header for decryption.
    
    Headers:
        X-Private-Key: base64_encoded_private_key
    
    Response:
        {
            "messages": [
                {
                    "id": 1,
                    "plaintext": "Hello!",
                    "signature_valid": true,
                    "sender_id": 1,
                    "sender_username": "alice",
                    "timestamp": "2024-01-29 12:00:00",
                    "is_sent": true
                },
                ...
            ]
        }
    """
    # Get private key from header
    private_key = request.headers.get('X-Private-Key')
    if not private_key:
        return jsonify({'error': 'Private key required'}), 400
    
    # Decode if base64 encoded
    try:
        import base64
        # Try to decode as base64 first
        if not private_key.startswith('-----'):
            private_key = base64.b64decode(private_key).decode('utf-8')
    except:
        pass  # Already in PEM format
    
    # Get and decrypt messages
    try:
        messages = message_service.get_conversation(
            request.user_id,
            other_user_id,
            private_key
        )
        return jsonify({'messages': messages})
    except Exception as e:
        return jsonify({'error': f'Failed to decrypt messages: {str(e)}'}), 500
