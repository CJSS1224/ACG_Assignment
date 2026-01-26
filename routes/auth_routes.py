"""
Authentication Routes - ST2504 Applied Cryptography

API routes for authentication:
- POST /api/register - Register new user (Solomon)
- POST /api/login - Login user (Solomon)
- GET /api/me - Get current user (Solomon)
"""

from flask import Blueprint, request, jsonify
from controllers.auth_controller import AuthController
from middleware.auth_middleware import token_required

auth_bp = Blueprint('auth', __name__)
auth_controller = AuthController()


@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user with RSA keypair generation."""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    result, status = auth_controller.register(username, password)
    return jsonify(result), status


@auth_bp.route('/login', methods=['POST'])
def login():
    """Authenticate a user."""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    result, status = auth_controller.login(username, password)
    return jsonify(result), status


@auth_bp.route('/me', methods=['GET'])
@token_required
def get_current_user(current_user):
    """Get current user info."""
    result, status = auth_controller.get_current_user(current_user['id'])
    return jsonify(result), status
