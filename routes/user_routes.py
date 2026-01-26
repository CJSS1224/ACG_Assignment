"""
User Routes - ST2504 Applied Cryptography

API routes for user operations:
- GET /api/users/online - Get online users (Solomon)
- GET /api/users/<id>/public-key - Get user's public key (Denise)
"""

from flask import Blueprint, jsonify
from controllers.user_controller import UserController
from middleware.auth_middleware import token_required

user_bp = Blueprint('users', __name__)
user_controller = UserController()


@user_bp.route('/users/online', methods=['GET'])
@token_required
def get_online_users(current_user):
    """Get list of currently online users."""
    result, status = user_controller.get_online_users(current_user['id'])
    return jsonify(result), status


@user_bp.route('/users/<int:user_id>/public-key', methods=['GET'])
@token_required
def get_user_public_key(current_user, user_id):
    """Get a user's public key."""
    result, status = user_controller.get_user_public_key(user_id)
    return jsonify(result), status
