"""
Message Service
===============
High-level message operations combining crypto and database.

This is the main interface for sending and receiving messages.
It orchestrates:
    - AES-GCM encryption (confidentiality)
    - RSA-OAEP key exchange
    - RSA-PSS signatures (non-repudiation)
    - Database storage

Functions:
    - encrypt_and_store_message: Encrypt message and save to DB
    - decrypt_message: Decrypt a message from DB
    - get_conversation: Get and decrypt all messages between users
"""

from typing import Optional
from crypto import (
    generate_aes_key,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    rsa_encrypt,
    rsa_decrypt,
    rsa_sign,
    rsa_verify
)
from models.database import Database


class MessageService:
    """Handles encrypted message operations."""
    
    def __init__(self, db: Database):
        """Initialize with database connection."""
        self.db = db
    
    def encrypt_and_store_message(
        self,
        plaintext: str,
        sender_id: int,
        sender_private_key: str,
        sender_public_key: str,
        recipient_id: int,
        recipient_public_key: str
    ) -> Optional[int]:
        """
        Encrypt a message and store it in the database.
        
        Process:
            1. Generate random AES-256 key
            2. Encrypt message with AES-GCM
            3. Encrypt AES key for both recipient and sender (RSA-OAEP)
            4. Sign ciphertext+nonce for non-repudiation (RSA-PSS)
            5. Store everything in database
        
        Args:
            plaintext: Message to send
            sender_id: Sender's user ID
            sender_private_key: Sender's RSA private key (PEM)
            sender_public_key: Sender's RSA public key (PEM)
            recipient_id: Recipient's user ID
            recipient_public_key: Recipient's RSA public key (PEM)
            
        Returns:
            int: Message ID if successful, None otherwise
        """
        # =================================================================
        # STEP 1: Generate random AES key for this message
        # =================================================================
        aes_key = generate_aes_key()  # 32 bytes (256 bits)
        
        # =================================================================
        # STEP 2: Encrypt message with AES-256-GCM
        # CONFIDENTIALITY AT REST
        # =================================================================
        ciphertext, nonce, tag = aes_gcm_encrypt(plaintext, aes_key)
        
        # =================================================================
        # STEP 3: Encrypt AES key for recipient (RSA-OAEP)
        # KEY EXCHANGE
        # =================================================================
        encrypted_key = rsa_encrypt(aes_key, recipient_public_key)
        
        # Also encrypt for sender so they can read their own messages
        encrypted_key_sender = rsa_encrypt(aes_key, sender_public_key)
        
        # =================================================================
        # STEP 4: Sign (ciphertext || nonce) with sender's private key
        # NON-REPUDIATION AT REST
        # =================================================================
        # Concatenate ciphertext and nonce for signing
        data_to_sign = ciphertext + nonce
        signature = rsa_sign(data_to_sign, sender_private_key)
        
        # =================================================================
        # STEP 5: Store in database
        # =================================================================
        message_id = self.db.store_message(
            sender_id=sender_id,
            recipient_id=recipient_id,
            ciphertext=ciphertext,
            nonce=nonce,
            tag=tag,
            encrypted_key=encrypted_key,
            encrypted_key_sender=encrypted_key_sender,
            signature=signature
        )
        
        # Update chat timestamp
        if message_id:
            self.db.get_or_create_chat(sender_id, recipient_id)
            self.db.update_chat_timestamp(sender_id, recipient_id)
        
        return message_id
    
    def decrypt_message(
        self,
        message: dict,
        user_id: int,
        user_private_key: str,
        verify_signature: bool = True
    ) -> dict:
        """
        Decrypt a message retrieved from the database.
        
        Process:
            1. Determine which encrypted key to use (recipient or sender)
            2. Decrypt AES key with RSA-OAEP
            3. Decrypt message with AES-GCM
            4. Optionally verify signature for non-repudiation
        
        Args:
            message: Message dict from database
            user_id: Current user's ID
            user_private_key: Current user's RSA private key (PEM)
            verify_signature: Whether to verify the signature
            
        Returns:
            dict: {
                'plaintext': str,
                'signature_valid': bool or None,
                'sender_id': int,
                'sender_username': str,
                'timestamp': str
            }
        """
        # =================================================================
        # STEP 1: Determine which encrypted key to use
        # =================================================================
        if message['sender_id'] == user_id:
            # User is the sender, use encrypted_key_sender
            encrypted_key = message['encrypted_key_sender']
        else:
            # User is the recipient, use encrypted_key
            encrypted_key = message['encrypted_key']
        
        # =================================================================
        # STEP 2: Decrypt AES key with RSA-OAEP
        # =================================================================
        aes_key = rsa_decrypt(encrypted_key, user_private_key)
        
        # =================================================================
        # STEP 3: Decrypt message with AES-GCM
        # =================================================================
        plaintext = aes_gcm_decrypt(
            message['ciphertext'],
            aes_key,
            message['nonce'],
            message['tag']
        )
        
        # =================================================================
        # STEP 4: Verify signature (optional)
        # =================================================================
        signature_valid = None
        if verify_signature and message.get('sender_public_key'):
            data_to_verify = message['ciphertext'] + message['nonce']
            signature_valid = rsa_verify(
                data_to_verify,
                message['signature'],
                message['sender_public_key']
            )
        
        return {
            'id': message['id'],
            'plaintext': plaintext,
            'signature_valid': signature_valid,
            'sender_id': message['sender_id'],
            'sender_username': message.get('sender_username', 'Unknown'),
            'timestamp': message.get('timestamp')
        }
    
    def get_conversation(
        self,
        user_id: int,
        other_user_id: int,
        user_private_key: str
    ) -> list:
        """
        Get and decrypt all messages in a conversation.
        
        Args:
            user_id: Current user's ID
            other_user_id: Other user's ID
            user_private_key: Current user's RSA private key
            
        Returns:
            list: List of decrypted messages with metadata
        """
        # Get encrypted messages from database
        messages = self.db.get_messages(user_id, other_user_id)
        
        # Decrypt each message
        decrypted = []
        for msg in messages:
            try:
                decrypted_msg = self.decrypt_message(msg, user_id, user_private_key)
                decrypted_msg['is_sent'] = (msg['sender_id'] == user_id)
                decrypted.append(decrypted_msg)
            except Exception as e:
                # If decryption fails, add placeholder
                decrypted.append({
                    'id': msg['id'],
                    'plaintext': '[Decryption failed]',
                    'signature_valid': False,
                    'sender_id': msg['sender_id'],
                    'sender_username': msg.get('sender_username', 'Unknown'),
                    'timestamp': msg.get('timestamp'),
                    'is_sent': (msg['sender_id'] == user_id),
                    'error': str(e)
                })
        
        return decrypted
