"""
Database Model - ST2504 Applied Cryptography
=============================================

Database operations using MySQL (Akash)
"""

import os
import mysql.connector
from mysql.connector import pooling
from dotenv import load_dotenv

load_dotenv()


class DatabaseModel:
    """Database operations with MySQL connection pooling."""
    
    _instance = None
    
    def __new__(cls):
        """Singleton pattern for single database pool."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._init_pool()
        self._initialized = True
    
    def _init_pool(self):
        """Create MySQL connection pool."""
        try:
            self.pool = pooling.MySQLConnectionPool(
                pool_name="securechat_pool",
                pool_size=5,
                host=os.getenv('DB_HOST', 'localhost'),
                user=os.getenv('DB_USER', 'root'),
                password=os.getenv('DB_PASSWORD', ''),
                database=os.getenv('DB_NAME', 'secure_messaging'),
                autocommit=True
            )
            print("[DB] MySQL connection pool initialized")
        except Exception as e:
            print(f"[DB] Failed to initialize pool: {e}")
            raise
    
    def _execute(self, query: str, params: tuple = None,
                 fetch_one: bool = False, fetch_all: bool = False):
        """Execute a database query."""
        conn = None
        cursor = None
        try:
            conn = self.pool.get_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute(query, params or ())
            
            if fetch_one:
                return cursor.fetchone()
            elif fetch_all:
                return cursor.fetchall()
            else:
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            print(f"[DB] Query error: {e}")
            raise
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    # ==================== USER OPERATIONS (Akash) ====================
    
    def get_user_by_id(self, user_id: int) -> dict:
        """Get user by ID."""
        query = "SELECT id, username, public_key FROM users WHERE id = %s"
        return self._execute(query, (user_id,), fetch_one=True)
    
    def get_user_by_username(self, username: str) -> dict:
        """Get user by username (includes encrypted private key)."""
        query = """
            SELECT id, username, password_hash, public_key,
                   encrypted_private_key, private_key_iv, private_key_salt
            FROM users WHERE username = %s
        """
        return self._execute(query, (username,), fetch_one=True)
    
    def create_user(self, username: str, password_hash: str, public_key: str,
                    encrypted_private_key: str, private_key_iv: str, private_key_salt: str) -> int:
        """Create a new user."""
        query = """
            INSERT INTO users (username, password_hash, public_key,
                             encrypted_private_key, private_key_iv, private_key_salt)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        try:
            return self._execute(query, (username, password_hash, public_key,
                                        encrypted_private_key, private_key_iv, private_key_salt))
        except Exception as e:
            if 'Duplicate entry' in str(e):
                return None
            raise
    
    # ==================== CHAT OPERATIONS (Charles) ====================
    
    def get_user_chats(self, user_id: int) -> list:
        """Get all chats for a user."""
        query = """
            SELECT 
                c.id as chat_id,
                CASE WHEN c.user1_id = %s THEN c.user2_id ELSE c.user1_id END as other_user_id,
                CASE WHEN c.user1_id = %s THEN u2.username ELSE u1.username END as other_username,
                CASE WHEN c.user1_id = %s THEN u2.public_key ELSE u1.public_key END as other_public_key
            FROM chats c
            JOIN users u1 ON c.user1_id = u1.id
            JOIN users u2 ON c.user2_id = u2.id
            WHERE c.user1_id = %s OR c.user2_id = %s
            ORDER BY c.last_message_at DESC
        """
        return self._execute(query, (user_id, user_id, user_id, user_id, user_id), fetch_all=True) or []
    
    def get_or_create_chat(self, user1_id: int, user2_id: int) -> int:
        """Get existing chat or create new one."""
        min_id, max_id = min(user1_id, user2_id), max(user1_id, user2_id)
        
        # Check if exists
        query = "SELECT id FROM chats WHERE user1_id = %s AND user2_id = %s"
        result = self._execute(query, (min_id, max_id), fetch_one=True)
        
        if result:
            return result['id']
        
        # Create new
        query = "INSERT INTO chats (user1_id, user2_id) VALUES (%s, %s)"
        return self._execute(query, (min_id, max_id))
    
    def update_chat_timestamp(self, user1_id: int, user2_id: int):
        """Update last message timestamp."""
        query = """
            UPDATE chats SET last_message_at = CURRENT_TIMESTAMP
            WHERE (user1_id = %s AND user2_id = %s) OR (user1_id = %s AND user2_id = %s)
        """
        self._execute(query, (user1_id, user2_id, user2_id, user1_id))
    
    # ==================== MESSAGE OPERATIONS (Akash) ====================
    
    def store_message(self, sender_id: int, recipient_id: int, encrypted_payload: str,
                      encrypted_key: str, encrypted_key_sender: str, iv: str,
                      signature: str, hmac: str) -> int:
        """Store an encrypted message."""
        query = """
            INSERT INTO messages (sender_id, recipient_id, encrypted_payload, encrypted_key,
                                 encrypted_key_sender, iv, signature, hmac)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        return self._execute(query, (sender_id, recipient_id, encrypted_payload, encrypted_key,
                                    encrypted_key_sender, iv, signature, hmac))
    
    def get_chat_messages(self, user1_id: int, user2_id: int) -> list:
        """Get messages between two users."""
        query = """
            SELECT m.*, u.public_key as sender_public_key
            FROM messages m
            JOIN users u ON u.id = m.sender_id
            WHERE (m.sender_id = %s AND m.recipient_id = %s)
               OR (m.sender_id = %s AND m.recipient_id = %s)
            ORDER BY m.timestamp ASC
        """
        return self._execute(query, (user1_id, user2_id, user2_id, user1_id), fetch_all=True) or []
