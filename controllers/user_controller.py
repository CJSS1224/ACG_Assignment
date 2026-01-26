"""
User Controller - ST2504 Applied Cryptography

This controller handles user-related business logic:
- Get online users (Solomon)
- Get user public key (Denise)

Uses DatabaseModel and ConnectionModel.
"""

from models.database_model import DatabaseModel
from models.connection_model import ConnectionModel


class UserController:
    """Controller for user operations."""
    
    def __init__(self):
        self.db = DatabaseModel()
        self.connections = ConnectionModel()
    
    def get_online_users(self, current_user_id: int) -> tuple:
        """
        Get list of currently online users.
        
        Returns:
            tuple of (list, status_code)
        """
        online_user_ids = self.connections.get_online_user_ids(exclude_user_id=current_user_id)
        
        users = []
        for uid in online_user_ids:
            user = self.db.get_user_by_id(uid)
            if user:
                users.append({
                    'id': user['id'],
                    'username': user['username'],
                    'public_key': user['public_key']
                })
        
        return users, 200
    
    def get_user_public_key(self, user_id: int) -> tuple:
        """
        Get a user's public key.
        
        Returns:
            tuple of (dict, status_code)
        """
        user = self.db.get_user_by_id(user_id)
        if not user:
            return {'error': 'User not found'}, 404
        
        return {
            'user_id': user['id'],
            'username': user['username'],
            'public_key': user['public_key']
        }, 200
