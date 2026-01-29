"""
Database Model
==============
Handles all database operations for SecureChat.

Tables:
    - users: User accounts and RSA keys
    - messages: Encrypted messages
    - chats: Conversation tracking

All cryptographic data is stored as Base64 strings for compatibility.
"""

import base64
import mysql.connector
from mysql.connector import Error
from datetime import datetime
from typing import Optional
from contextlib import contextmanager


class Database:
    """Database operations for SecureChat."""
    
    def __init__(self, host='localhost', user='root', password='', database='securechat'):
        """Initialize database connection parameters."""
        self.config = {
            'host': host,
            'user': user,
            'password': password,
            'database': database
        }
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections."""
        conn = None
        try:
            conn = mysql.connector.connect(**self.config)
            yield conn
        finally:
            if conn and conn.is_connected():
                conn.close()
    
    # =========================================================================
    # UTILITY FUNCTIONS
    # =========================================================================
    
    @staticmethod
    def to_base64(data: bytes) -> str:
        """Convert bytes to base64 string for storage."""
        return base64.b64encode(data).decode('utf-8')
    
    @staticmethod
    def from_base64(data: str) -> bytes:
        """Convert base64 string back to bytes."""
        return base64.b64decode(data.encode('utf-8'))
    
    # =========================================================================
    # USER OPERATIONS
    # =========================================================================
    
    def create_user(self, username: str, password_hash: str, public_key: str,
                    encrypted_private_key: bytes, nonce: bytes, tag: bytes, salt: bytes) -> Optional[int]:
        """
        Create a new user account.
        
        Args:
            username: Unique username
            password_hash: bcrypt hashed password
            public_key: RSA public key (PEM format)
            encrypted_private_key: AES-GCM encrypted private key
            nonce: AES-GCM nonce
            tag: AES-GCM authentication tag
            salt: PBKDF2 salt
            
        Returns:
            int: New user ID, or None if failed
        """
        query = """
            INSERT INTO users 
            (username, password_hash, public_key, encrypted_private_key, 
             private_key_nonce, private_key_tag, private_key_salt)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (
                    username,
                    password_hash,
                    public_key,
                    self.to_base64(encrypted_private_key),
                    self.to_base64(nonce),
                    self.to_base64(tag),
                    self.to_base64(salt)
                ))
                conn.commit()
                return cursor.lastrowid
        except Error as e:
            print(f"[DB] Error creating user: {e}")
            print(f"[DB] MySQL Error Code: {e.errno if hasattr(e, 'errno') else 'N/A'}")
            print(f"[DB] MySQL Error Message: {e.msg if hasattr(e, 'msg') else str(e)}")
            return None
        except Exception as e:
            print(f"[DB] Unexpected error creating user: {type(e).__name__}: {e}")
            return None
    
    def get_user_by_username(self, username: str) -> Optional[dict]:
        """Get user by username."""
        query = "SELECT * FROM users WHERE username = %s"
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(query, (username,))
                user = cursor.fetchone()
                
                if user:
                    # Convert base64 fields back to bytes
                    user['encrypted_private_key'] = self.from_base64(user['encrypted_private_key'])
                    user['private_key_nonce'] = self.from_base64(user['private_key_nonce'])
                    user['private_key_tag'] = self.from_base64(user['private_key_tag'])
                    user['private_key_salt'] = self.from_base64(user['private_key_salt'])
                
                return user
        except Error as e:
            print(f"[DB] Error getting user: {e}")
            return None
    
    def get_user_by_id(self, user_id: int) -> Optional[dict]:
        """Get user by ID."""
        query = "SELECT id, username, public_key FROM users WHERE id = %s"
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(query, (user_id,))
                return cursor.fetchone()
        except Error as e:
            print(f"[DB] Error getting user: {e}")
            return None
    
    def get_all_users(self, exclude_id: int = None) -> list:
        """Get all users (excluding specified ID)."""
        if exclude_id:
            query = "SELECT id, username, public_key FROM users WHERE id != %s"
            params = (exclude_id,)
        else:
            query = "SELECT id, username, public_key FROM users"
            params = ()
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(query, params)
                return cursor.fetchall()
        except Error as e:
            print(f"[DB] Error getting users: {e}")
            return []
    
    # =========================================================================
    # MESSAGE OPERATIONS
    # =========================================================================
    
    def store_message(self, sender_id: int, recipient_id: int, ciphertext: bytes,
                      nonce: bytes, tag: bytes, encrypted_key: bytes,
                      encrypted_key_sender: bytes, signature: bytes) -> Optional[int]:
        """
        Store an encrypted message.
        
        Args:
            sender_id: Sender's user ID
            recipient_id: Recipient's user ID
            ciphertext: AES-GCM encrypted message
            nonce: AES-GCM nonce
            tag: AES-GCM authentication tag
            encrypted_key: AES key encrypted for recipient
            encrypted_key_sender: AES key encrypted for sender
            signature: RSA-PSS signature
            
        Returns:
            int: Message ID, or None if failed
        """
        query = """
            INSERT INTO messages 
            (sender_id, recipient_id, ciphertext, nonce, tag, 
             encrypted_key, encrypted_key_sender, signature)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (
                    sender_id,
                    recipient_id,
                    self.to_base64(ciphertext),
                    self.to_base64(nonce),
                    self.to_base64(tag),
                    self.to_base64(encrypted_key),
                    self.to_base64(encrypted_key_sender),
                    self.to_base64(signature)
                ))
                conn.commit()
                return cursor.lastrowid
        except Error as e:
            print(f"[DB] Error storing message: {e}")
            return None
    
    def get_messages(self, user1_id: int, user2_id: int, limit: int = 100) -> list:
        """
        Get messages between two users.
        
        Returns messages in chronological order.
        """
        query = """
            SELECT m.*, u.username as sender_username, u.public_key as sender_public_key
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE (m.sender_id = %s AND m.recipient_id = %s)
               OR (m.sender_id = %s AND m.recipient_id = %s)
            ORDER BY m.timestamp ASC
            LIMIT %s
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(query, (user1_id, user2_id, user2_id, user1_id, limit))
                messages = cursor.fetchall()
                
                # Convert base64 fields back to bytes
                for msg in messages:
                    msg['ciphertext'] = self.from_base64(msg['ciphertext'])
                    msg['nonce'] = self.from_base64(msg['nonce'])
                    msg['tag'] = self.from_base64(msg['tag'])
                    msg['encrypted_key'] = self.from_base64(msg['encrypted_key'])
                    msg['encrypted_key_sender'] = self.from_base64(msg['encrypted_key_sender'])
                    msg['signature'] = self.from_base64(msg['signature'])
                    # Convert timestamp to string
                    if msg['timestamp']:
                        msg['timestamp'] = msg['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                
                return messages
        except Error as e:
            print(f"[DB] Error getting messages: {e}")
            return []
    
    def get_message_by_id(self, message_id: int) -> Optional[dict]:
        """Get a single message by ID."""
        query = """
            SELECT m.*, u.username as sender_username, u.public_key as sender_public_key
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.id = %s
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(query, (message_id,))
                msg = cursor.fetchone()
                
                if msg:
                    msg['ciphertext'] = self.from_base64(msg['ciphertext'])
                    msg['nonce'] = self.from_base64(msg['nonce'])
                    msg['tag'] = self.from_base64(msg['tag'])
                    msg['encrypted_key'] = self.from_base64(msg['encrypted_key'])
                    msg['encrypted_key_sender'] = self.from_base64(msg['encrypted_key_sender'])
                    msg['signature'] = self.from_base64(msg['signature'])
                    if msg['timestamp']:
                        msg['timestamp'] = msg['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                
                return msg
        except Error as e:
            print(f"[DB] Error getting message: {e}")
            return None
    
    # =========================================================================
    # CHAT OPERATIONS
    # =========================================================================
    
    def get_or_create_chat(self, user1_id: int, user2_id: int) -> Optional[int]:
        """Get or create a chat between two users."""
        # Ensure consistent ordering
        if user1_id > user2_id:
            user1_id, user2_id = user2_id, user1_id
        
        # Try to get existing chat
        query = "SELECT id FROM chats WHERE user1_id = %s AND user2_id = %s"
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (user1_id, user2_id))
                result = cursor.fetchone()
                
                if result:
                    return result[0]
                
                # Create new chat
                cursor.execute(
                    "INSERT INTO chats (user1_id, user2_id) VALUES (%s, %s)",
                    (user1_id, user2_id)
                )
                conn.commit()
                return cursor.lastrowid
        except Error as e:
            print(f"[DB] Error with chat: {e}")
            return None
    
    def update_chat_timestamp(self, user1_id: int, user2_id: int):
        """Update the last message timestamp for a chat."""
        if user1_id > user2_id:
            user1_id, user2_id = user2_id, user1_id
        
        query = """
            UPDATE chats SET last_message_at = NOW() 
            WHERE user1_id = %s AND user2_id = %s
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (user1_id, user2_id))
                conn.commit()
        except Error as e:
            print(f"[DB] Error updating chat: {e}")
    
    def get_user_chats(self, user_id: int) -> list:
        """Get all chats for a user."""
        query = """
            SELECT c.id as chat_id,
                   CASE WHEN c.user1_id = %s THEN c.user2_id ELSE c.user1_id END as other_user_id,
                   u.username as other_username,
                   u.public_key as other_public_key,
                   c.last_message_at
            FROM chats c
            JOIN users u ON (
                CASE WHEN c.user1_id = %s THEN c.user2_id ELSE c.user1_id END = u.id
            )
            WHERE c.user1_id = %s OR c.user2_id = %s
            ORDER BY c.last_message_at DESC
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(query, (user_id, user_id, user_id, user_id))
                chats = cursor.fetchall()
                
                for chat in chats:
                    if chat['last_message_at']:
                        chat['last_message_at'] = chat['last_message_at'].strftime('%Y-%m-%d %H:%M:%S')
                
                return chats
        except Error as e:
            print(f"[DB] Error getting chats: {e}")
            return []