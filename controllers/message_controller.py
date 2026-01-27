"""
Message Controller - ST2504 Applied Cryptography

This controller handles message-related business logic:
- Encrypt and send messages (Charles, Amir, Yong Cheng, Denise)
- Handle real-time message delivery (Solomon)

Uses CryptoModel, DatabaseModel, and ConnectionModel.
"""

from models.database_model import DatabaseModel
from models.crypto_model import CryptoModel
from models.connection_model import ConnectionModel


class MessageController:
    """Controller for message operations."""
    
    def __init__(self):
        self.db = DatabaseModel()
        self.crypto = CryptoModel()
        self.connections = ConnectionModel()
    
    def send_message(self, sender_id: int, recipient_id: int, 
                     plaintext: str, sender_private_key: str) -> dict:
        """
        Encrypt and store a message.
        
        Security Model (all crypto in Python):
        - AES-256-CTR encryption for confidentiality (Charles)
        - RSA-OAEP for key exchange (Denise)
        - RSA signatures for non-repudiation (Yong Cheng)
        - HMAC-SHA256 for integrity (Amir)
        
        Returns:
            dict with message_id or error
        """
        if not recipient_id:
            return {'error': 'Recipient ID required'}
        
        if not plaintext:
            return {'error': 'Message cannot be empty'}
        
        if not sender_private_key:
            return {'error': 'Private key required for signing'}
        
        # Get sender and recipient info
        sender = self.db.get_user_by_id(sender_id)
        recipient = self.db.get_user_by_id(recipient_id)
        
        if not sender or not recipient:
            return {'error': 'User not found'}
        
        try:
            # =================================================================
            # SERVER-SIDE ENCRYPTION (All cryptography in Python)
            # =================================================================
            
            # Encrypt message using crypto model
            encrypted_data = self.crypto.encrypt_message(
                plaintext=plaintext,
                recipient_public_key=recipient['public_key'],
                sender_private_key=sender_private_key,
                sender_public_key=sender['public_key']
            )
            
            # Store encrypted message in database (at-rest encryption)
            message_id = self.db.store_message(
                sender_id=sender_id,
                recipient_id=recipient_id,
                encrypted_payload=encrypted_data['encrypted_payload'],
                encrypted_key=encrypted_data['encrypted_key'],
                encrypted_key_sender=encrypted_data['encrypted_key_sender'],
                iv=encrypted_data['iv'],
                signature=encrypted_data['signature'],
                hmac=encrypted_data['hmac']
            )
            
            # Update chat timestamp
            self.db.update_chat_timestamp(sender_id, recipient_id)
            
            return {
                'success': True,
                'message_id': message_id,
                'sender': sender,
                'sender_public_key': sender['public_key'],
                'recipient_id': recipient_id,
                # Return encrypted data for transit (client will decrypt)
                'encrypted_payload': encrypted_data['encrypted_payload'],
                'encrypted_key': encrypted_data['encrypted_key'],
                'iv': encrypted_data['iv'],
                'signature': encrypted_data['signature']
            }
            
        except Exception as e:
            print(f"[ERROR] Failed to encrypt/store message: {e}")
            import traceback
            traceback.print_exc()
            return {'error': 'Failed to send message'}
    
    def is_recipient_online(self, recipient_id: int) -> bool:
        """Check if recipient is online."""
        return self.connections.is_user_online(recipient_id)
    
    def get_recipient_session(self, recipient_id: int) -> str:
        """Get recipient's session ID for WebSocket delivery."""
        return self.connections.get_session_id(recipient_id)
