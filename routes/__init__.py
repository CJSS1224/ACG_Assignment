"""
Routes Package
==============
All HTTP and WebSocket routes for SecureChat.

Modules:
    - auth: Authentication endpoints (/api/register, /api/login)
    - api: REST API endpoints (/api/users, /api/chats, /api/messages)
    - socket: WebSocket event handlers
"""

from .auth import auth_bp, init_auth, token_required
from .api import api_bp, init_api
from .socket import register_socket_events, get_online_user_ids

__all__ = [
    'auth_bp', 'init_auth', 'token_required',
    'api_bp', 'init_api',
    'register_socket_events', 'get_online_user_ids'
]
