"""
Routes Package
==============
All HTTP and WebSocket routes for SecureChat.
Implemented by: Solomon (Message Service & API Specialist)

Modules:
    - auth: Authentication endpoints (/api/register, /api/login) [Solomon]
    - api: REST API endpoints (/api/users, /api/chats, /api/messages) [Solomon]
    - socket: WebSocket event handlers [Solomon]
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from routes.auth import auth_bp, init_auth, token_required
from routes.api import api_bp, init_api
from routes.socket import register_socket_events, get_online_user_ids

__all__ = [
    'auth_bp', 'init_auth', 'token_required',
    'api_bp', 'init_api',
    'register_socket_events', 'get_online_user_ids'
]
