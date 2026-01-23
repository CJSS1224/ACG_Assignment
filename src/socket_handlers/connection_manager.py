"""
Connection Manager

Manages WebSocket connections and user sessions.
Tracks which users are online and their socket session IDs.
"""

from src.models.user_model import (
    create_session, delete_session, delete_user_sessions
)

# Store active connections: {session_id: user_id}
active_connections = {}

# Store user to session mapping: {user_id: session_id}
user_sessions = {}


def add_connection(session_id, user_id):
    """
    Add a new connection.
    
    Args:
        session_id: Socket session ID
        user_id: User ID
    """
    active_connections[session_id] = user_id
    user_sessions[user_id] = session_id
    create_session(user_id, session_id)


def remove_connection(session_id):
    """
    Remove a connection by session ID.
    
    Args:
        session_id: Socket session ID
        
    Returns:
        user_id if found, None otherwise
    """
    if session_id in active_connections:
        user_id = active_connections[session_id]
        delete_session(session_id)
        del active_connections[session_id]
        if user_id in user_sessions:
            del user_sessions[user_id]
        return user_id
    return None


def remove_user_session(user_id):
    """
    Remove all sessions for a user (used on logout).
    
    Args:
        user_id: User ID
    """
    if user_id in user_sessions:
        session_id = user_sessions[user_id]
        delete_session(session_id)
        if session_id in active_connections:
            del active_connections[session_id]
        del user_sessions[user_id]
    delete_user_sessions(user_id)


def get_user_id(session_id):
    """
    Get user ID for a session.
    
    Args:
        session_id: Socket session ID
        
    Returns:
        User ID or None
    """
    return active_connections.get(session_id)


def get_session_id(user_id):
    """
    Get session ID for a user.
    
    Args:
        user_id: User ID
        
    Returns:
        Session ID or None
    """
    return user_sessions.get(user_id)


def is_user_online(user_id):
    """
    Check if a user is online.
    
    Args:
        user_id: User ID
        
    Returns:
        True if online, False otherwise
    """
    return user_id in user_sessions


def is_session_valid(session_id):
    """
    Check if a session is valid.
    
    Args:
        session_id: Socket session ID
        
    Returns:
        True if valid, False otherwise
    """
    return session_id in active_connections
