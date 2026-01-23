"""
Chat Routes

Handles chat-related endpoints like creating chats and getting messages.
"""

from flask import Blueprint, request, jsonify

from src.models.user_model import get_user_by_id
from src.models.message_model import (
    get_messages_between_users, mark_messages_as_read,
    get_or_create_chat, get_user_chats
)
from src.services.auth_service import token_required

# Create blueprint
chat_bp = Blueprint('chats', __name__, url_prefix='/api/chats')


@chat_bp.route('', methods=['GET'])
@token_required
def get_chats():
    """Get all chats for the current user."""
    chats = get_user_chats(request.user['id'])
    return jsonify(chats or []), 200


@chat_bp.route('', methods=['POST'])
@token_required
def create_chat():
    """Create a new chat with another user."""
    data = request.get_json()
    
    if not data or 'user_id' not in data:
        return jsonify({'error': 'user_id required'}), 400
    
    other_user_id = data['user_id']
    current_user_id = request.user['id']
    
    if other_user_id == current_user_id:
        return jsonify({'error': 'Cannot create chat with yourself'}), 400
    
    # Verify other user exists
    other_user = get_user_by_id(other_user_id)
    if not other_user:
        return jsonify({'error': 'User not found'}), 404
    
    # Get or create chat
    chat_id = get_or_create_chat(current_user_id, other_user_id)
    
    return jsonify({
        'chat_id': chat_id,
        'other_user': {
            'id': other_user['id'],
            'username': other_user['username'],
            'public_key': other_user['public_key']
        }
    }), 201


@chat_bp.route('/<int:other_user_id>/messages', methods=['GET'])
@token_required
def get_chat_messages(other_user_id):
    """Get messages between current user and another user."""
    messages = get_messages_between_users(request.user['id'], other_user_id)
    
    # Mark messages as read
    mark_messages_as_read(request.user['id'], other_user_id)
    
    return jsonify(messages or []), 200
