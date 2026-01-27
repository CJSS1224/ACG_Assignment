"""
Chat Controller - ST2504 Applied Cryptography

This controller handles chat-related business logic:
- Get user chats (Charles)
- Create chat (Charles)
- Get and decrypt messages (Charles, Akash)

Uses DatabaseModel and CryptoModel.
"""

from models.database_model import DatabaseModel
from models.crypto_model import CryptoModel


class ChatController:
    """Controller for chat operations."""
    
    def __init__(self):
        self.db = DatabaseModel()
        self.crypto = CryptoModel()
    
    def get_user_chats(self, user_id: int) -> tuple:
        """
        Get all chats for a user.
        
        Returns:
            tuple of (list, status_code)
        """
        chats = self.db.get_user_chats(user_id)
        print(f"[API] get_chats for user {user_id}: found {len(chats) if chats else 0} chats")
        if chats:
            for c in chats:
                print(f"[API]   - Chat {c.get('chat_id')} with user {c.get('other_user_id')} ({c.get('other_username')})")
        return chats or [], 200
    
    def create_chat(self, current_user_id: int, other_user_id: int) -> tuple:
        """
        Create or get existing chat with another user.
        
        Returns:
            tuple of (dict, status_code)
        """
        if not other_user_id:
            return {'error': 'user_id required'}, 400
        
        other_user = self.db.get_user_by_id(other_user_id)
        if not other_user:
            return {'error': 'User not found'}, 404
        
        chat_id = self.db.get_or_create_chat(current_user_id, other_user_id)
        
        return {
            'chat_id': chat_id,
            'other_user': {
                'id': other_user['id'],
                'username': other_user['username'],
                'public_key': other_user['public_key']
            }
        }, 200
    
    def get_chat_messages(self, current_user_id: int, other_user_id: int, 
                          private_key: str = None) -> tuple:
        """
        Get messages for a chat - returns encrypted data for client-side decryption.
        
        Args:
            current_user_id: ID of current user
            other_user_id: ID of chat partner
            private_key: Private key for decryption (optional, for backward compatibility)
        
        Returns:
            tuple of (list, status_code)
        """
        messages = self.db.get_chat_messages(current_user_id, other_user_id)
        
        # Get sender's public key for signature verification
        other_user = self.db.get_user_by_id(other_user_id)
        other_public_key = other_user['public_key'] if other_user else None
        
        result_messages = []
        for msg in messages:
            # Determine which encrypted_key to use based on who is requesting
            # If current user is sender, use encrypted_key_sender
            # If current user is recipient, use encrypted_key
            if msg['sender_id'] == current_user_id:
                encrypted_key = msg.get('encrypted_key_sender') or msg['encrypted_key']
                sender_public_key = None  # Own message, no need to verify
            else:
                encrypted_key = msg['encrypted_key']
                sender_public_key = other_public_key
            
            result_messages.append({
                'id': msg['id'],
                'sender_id': msg['sender_id'],
                'recipient_id': msg['recipient_id'],
                # Encrypted data for client-side decryption
                'encrypted_payload': msg['encrypted_payload'],
                'encrypted_key': encrypted_key,
                'iv': msg['iv'],
                'signature': msg['signature'],
                'sender_public_key': sender_public_key,
                'timestamp': msg['timestamp'].isoformat() if msg['timestamp'] else None
            })
        
        return result_messages, 200
