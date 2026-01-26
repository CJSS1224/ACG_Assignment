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
        Get and optionally decrypt messages for a chat.
        
        Args:
            current_user_id: ID of current user
            other_user_id: ID of chat partner
            private_key: Private key for decryption (optional)
        
        Returns:
            tuple of (list, status_code)
        """
        messages = self.db.get_chat_messages(current_user_id, other_user_id)
        
        result_messages = []
        for msg in messages:
            try:
                if private_key:
                    # Get sender's public key for signature verification
                    sender_public_key = None
                    if msg['sender_id'] != current_user_id:
                        sender = self.db.get_user_by_id(msg['sender_id'])
                        sender_public_key = sender['public_key'] if sender else None
                    
                    # Decrypt message (Charles)
                    decrypted = self.crypto.decrypt_message(
                        encrypted_data={
                            'encrypted_payload': msg['encrypted_payload'],
                            'encrypted_key': msg['encrypted_key'],
                            'encrypted_key_sender': msg.get('encrypted_key_sender'),
                            'iv': msg['iv'],
                            'signature': msg['signature']
                        },
                        private_key=private_key,
                        sender_public_key=sender_public_key
                    )
                    
                    result_messages.append({
                        'id': msg['id'],
                        'sender_id': msg['sender_id'],
                        'recipient_id': msg['recipient_id'],
                        'plaintext': decrypted['plaintext'],
                        'signature_valid': decrypted['signature_valid'],
                        'timestamp': msg['timestamp'].isoformat() if msg['timestamp'] else None
                    })
                else:
                    # No private key - return encrypted indicator
                    result_messages.append({
                        'id': msg['id'],
                        'sender_id': msg['sender_id'],
                        'recipient_id': msg['recipient_id'],
                        'encrypted': True,
                        'timestamp': msg['timestamp'].isoformat() if msg['timestamp'] else None
                    })
                    
            except Exception as e:
                print(f"[ERROR] Failed to decrypt message {msg['id']}: {e}")
                result_messages.append({
                    'id': msg['id'],
                    'sender_id': msg['sender_id'],
                    'recipient_id': msg['recipient_id'],
                    'plaintext': '[Decryption failed]',
                    'error': True,
                    'timestamp': msg['timestamp'].isoformat() if msg['timestamp'] else None
                })
        
        return result_messages, 200
