"""
Connection Model - ST2504 Applied Cryptography

This model manages WebSocket connections:
- Track active connections (Solomon)
- Map users to sessions
- Online status management

In-memory storage for real-time connection tracking.
"""


class ConnectionModel:
    """
    Singleton model for managing WebSocket connections.
    Tracks which users are online and their session IDs.
    """
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self.active_connections = {}  # {session_id: user_id}
        self.user_sessions = {}       # {user_id: session_id}
        self._initialized = True
    
    def add_connection(self, session_id: str, user_id: int) -> None:
        """Add a new connection."""
        self.active_connections[session_id] = user_id
        self.user_sessions[user_id] = session_id
    
    def remove_connection(self, session_id: str) -> int:
        """Remove a connection and return the user_id."""
        user_id = self.active_connections.pop(session_id, None)
        if user_id:
            self.user_sessions.pop(user_id, None)
        return user_id
    
    def get_user_id(self, session_id: str) -> int:
        """Get user_id from session_id."""
        return self.active_connections.get(session_id)
    
    def get_session_id(self, user_id: int) -> str:
        """Get session_id from user_id."""
        return self.user_sessions.get(user_id)
    
    def is_user_online(self, user_id: int) -> bool:
        """Check if user is online."""
        return user_id in self.user_sessions
    
    def get_online_user_ids(self, exclude_user_id: int = None) -> set:
        """Get set of online user IDs, optionally excluding one."""
        online = set(self.active_connections.values())
        if exclude_user_id:
            online.discard(exclude_user_id)
        return online
    
    def is_session_valid(self, session_id: str) -> bool:
        """Check if session is valid."""
        return session_id in self.active_connections
