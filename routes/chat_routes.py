"""
Chat Routes - ST2504 Applied Cryptography

API routes for chat operations:
- GET /api/chats - Get user's chats (Charles)
- POST /api/chats - Create a chat (Charles)
- POST /api/chats/<id>/messages - Get chat messages (Charles, Akash)
"""

from flask import Blueprint, request, jsonify
from controllers.chat_controller import ChatController
from middleware.auth_middleware import token_required

chat_bp = Blueprint('chats', __name__)
chat_controller = ChatController()


@chat_bp.route('/chats', methods=['GET'])
@token_required
def get_chats(current_user):
    """Get all chats for current user."""
    result, status = chat_controller.get_user_chats(current_user['id'])
    return jsonify(result), status


@chat_bp.route('/chats', methods=['POST'])
@token_required
def create_chat(current_user):
    """Create or get existing chat with another user."""
    data = request.get_json()
    other_user_id = data.get('user_id')
    
    result, status = chat_controller.create_chat(current_user['id'], other_user_id)
    return jsonify(result), status


@chat_bp.route('/chats/<int:other_user_id>/messages', methods=['POST'])
@token_required
def get_chat_messages(current_user, other_user_id):
    """
    Get and decrypt messages for a chat.
    Client provides their private key in request body for decryption.
    """
    data = request.get_json() or {}
    private_key = data.get('private_key')
    
    result, status = chat_controller.get_chat_messages(
        current_user['id'], 
        other_user_id, 
        private_key
    )
    return jsonify(result), status
