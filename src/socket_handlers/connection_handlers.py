"""
Connection Handlers

Handles WebSocket connection and disconnection events.
"""

from flask_socketio import emit, join_room, disconnect
from flask import request

from src.models.user_model import get_user_by_id, get_online_users
from src.services.auth_service import verify_token
from src.socket_handlers.connection_manager import (
    add_connection, remove_connection, get_user_id
)


def handle_connect():
    """
    Handle client connection.
    
    Verifies JWT token and registers the connection.
    """
    # Get token from query parameter
    token = request.args.get('token')
    
    if not token:
        print(f"[SOCKET] Connection rejected: No token")
        disconnect()
        return False
    
    # Verify token
    payload = verify_token(token)
    if not payload:
        print(f"[SOCKET] Connection rejected: Invalid token")
        disconnect()
        return False
    
    user_id = payload['id']
    username = payload['username']
    session_id = request.sid
    
    # Store connection
    add_connection(session_id, user_id)
    
    # Join personal room
    join_room(f"user_{user_id}")
    
    print(f"[SOCKET] User {username} (ID: {user_id}) connected")
    
    # Broadcast user online status
    emit('user_online', {
        'user_id': user_id,
        'username': username
    }, broadcast=True, include_self=False)
    
    return True


def handle_disconnect():
    """Handle client disconnection."""
    session_id = request.sid
    user_id = remove_connection(session_id)
    
    if user_id:
        # Get username for broadcast
        user = get_user_by_id(user_id)
        username = user['username'] if user else 'Unknown'
        
        print(f"[SOCKET] User {username} (ID: {user_id}) disconnected")
        
        # Broadcast user offline status
        emit('user_offline', {
            'user_id': user_id,
            'username': username
        }, broadcast=True)


def handle_get_online_users():
    """Get list of currently online users."""
    session_id = request.sid
    user_id = get_user_id(session_id)
    
    if not user_id:
        emit('error', {'message': 'Not authenticated'})
        return
    
    users = get_online_users(exclude_user_id=user_id)
    
    emit('online_users_list', {
        'users': users or []
    })
