"""
Socket Handlers Package

Contains all WebSocket event handlers.
"""

from src.socket_handlers.connection_manager import (
    add_connection, remove_connection, remove_user_session,
    get_user_id, get_session_id, is_user_online, is_session_valid
)
from src.socket_handlers.connection_handlers import (
    handle_connect, handle_disconnect, handle_get_online_users
)
from src.socket_handlers.message_handlers import (
    handle_send_message, handle_typing, handle_stop_typing
)

__all__ = [
    # Connection manager
    'add_connection', 'remove_connection', 'remove_user_session',
    'get_user_id', 'get_session_id', 'is_user_online', 'is_session_valid',
    # Connection handlers
    'handle_connect', 'handle_disconnect', 'handle_get_online_users',
    # Message handlers
    'handle_send_message', 'handle_typing', 'handle_stop_typing'
]
