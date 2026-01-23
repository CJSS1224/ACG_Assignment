"""
User Routes

Handles user-related endpoints like getting online users and public keys.
"""

from flask import Blueprint, request, jsonify

from src.models.user_model import (
    get_user_by_id, get_online_users, get_all_users
)
from src.services.auth_service import token_required

# Create blueprint
user_bp = Blueprint('users', __name__, url_prefix='/api/users')


@user_bp.route('/online', methods=['GET'])
@token_required
def get_online_users_route():
    """Get list of online users (excluding current user)."""
    users = get_online_users(exclude_user_id=request.user['id'])
    return jsonify(users or []), 200


@user_bp.route('', methods=['GET'])
@token_required
def get_all_users_route():
    """Get list of all users (excluding current user)."""
    users = get_all_users(exclude_user_id=request.user['id'])
    # Remove sensitive data
    safe_users = [
        {'id': u['id'], 'username': u['username'], 'public_key': u['public_key']} 
        for u in users
    ]
    return jsonify(safe_users), 200


@user_bp.route('/<int:user_id>/public-key', methods=['GET'])
@token_required
def get_user_public_key(user_id):
    """Get a user's public key."""
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'user_id': user['id'],
        'username': user['username'],
        'public_key': user['public_key']
    }), 200
