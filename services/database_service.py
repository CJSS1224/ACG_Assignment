"""
Database Service - ST2504 Applied Cryptography

This module handles all database operations:
- User management (Akash)
- Message storage (Akash)
- Chat management (Charles)

Database: MySQL
All messages are stored encrypted (at-rest encryption).
"""

import os
import mysql.connector
from mysql.connector import pooling
from typing import Optional, List, Dict, Any
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


class DatabaseService:
    
    def __init__(self):
        self.pool = None
        self._init_pool()
    
    def _init_pool(self):
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
            print("[DB] Connection pool initialized")
        except Exception as e:
            print(f"[DB] Failed to initialize pool: {e}")
            raise
    
    def _execute(self, query: str, params: tuple = None,
        fetch_one: bool = False, fetch_all: bool = False) -> Any:
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
            print(f"[DB] Query: {query}")
            raise
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    # ==========================================================================
    # USER OPERATIONS - Akash
    # ==========================================================================
    
    def create_user(self, username: str, password_hash: str,
        public_key: str = None) -> Optional[int]:
        query = """
            INSERT INTO users (username, password_hash, public_key)
            VALUES (%s, %s, %s)
        """
        try:
            return self._execute(query, (username, password_hash, public_key))
        except Exception as e:
            if 'Duplicate entry' in str(e):
                return None
            raise
    
    def get_user_by_username(self, username: str) -> Optional[Dict]:
        query = """
            SELECT id, username, password_hash, public_key, created_at, last_login
            FROM users WHERE username = %s
        """
        return self._execute(query, (username,), fetch_one=True)
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        query = """
            SELECT id, username, public_key, created_at, last_login
            FROM users WHERE id = %s
        """
        return self._execute(query, (user_id,), fetch_one=True)
    
    def update_last_login(self, user_id: int) -> None:
        query = "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s"
        self._execute(query, (user_id,))
    
    def get_all_users(self, exclude_user_id: int = None) -> List[Dict]:
        if exclude_user_id:
            query = """
                SELECT id, username, public_key FROM users 
                WHERE id != %s ORDER BY username
            """
            return self._execute(query, (exclude_user_id,), fetch_all=True) or []
        else:
            query = "SELECT id, username, public_key FROM users ORDER BY username"
            return self._execute(query, fetch_all=True) or []
    
    # ==========================================================================
    # MESSAGE OPERATIONS - Akash
    # ==========================================================================
    
    def store_message(self, sender_id: int, recipient_id: int,
        encrypted_payload: str, encrypted_key: str,
        encrypted_key_sender: str, iv: str,
        signature: str, hmac: str) -> int:
        query = """
            INSERT INTO messages 
            (sender_id, recipient_id, encrypted_payload, encrypted_key, 
             encrypted_key_sender, iv, signature, hmac)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        return self._execute(query, (
            sender_id, recipient_id, encrypted_payload, encrypted_key,
            encrypted_key_sender, iv, signature, hmac
        ))
    
    def get_chat_messages(self, user1_id: int, user2_id: int,
        limit: int = 100) -> List[Dict]:
        query = """
            SELECT id, sender_id, recipient_id, encrypted_payload, 
                   encrypted_key, encrypted_key_sender, iv, signature, 
                   hmac, timestamp
            FROM messages
            WHERE (sender_id = %s AND recipient_id = %s)
               OR (sender_id = %s AND recipient_id = %s)
            ORDER BY timestamp ASC
            LIMIT %s
        """
        return self._execute(
            query,
            (user1_id, user2_id, user2_id, user1_id, limit),
            fetch_all=True
        ) or []
    
    # ==========================================================================
    # CHAT OPERATIONS - Charles
    # ==========================================================================
    
    def get_or_create_chat(self, user1_id: int, user2_id: int) -> int:
        if user1_id > user2_id:
            user1_id, user2_id = user2_id, user1_id
        
        query = """
            SELECT id FROM chats
            WHERE (user1_id = %s AND user2_id = %s)
               OR (user1_id = %s AND user2_id = %s)
            LIMIT 1
        """
        result = self._execute(
            query,
            (user1_id, user2_id, user2_id, user1_id),
            fetch_one=True
        )
        
        if result:
            return result['id']
        
        query = "INSERT INTO chats (user1_id, user2_id) VALUES (%s, %s)"
        return self._execute(query, (user1_id, user2_id))
    
    def get_user_chats(self, user_id: int) -> List[Dict]:
        query = """
            SELECT 
                c.id as chat_id,
                CASE 
                    WHEN c.user1_id = %s THEN c.user2_id 
                    ELSE c.user1_id 
                END as other_user_id,
                CASE 
                    WHEN c.user1_id = %s THEN u2.username 
                    ELSE u1.username 
                END as other_username,
                CASE 
                    WHEN c.user1_id = %s THEN u2.public_key 
                    ELSE u1.public_key 
                END as other_public_key,
                c.last_message_at
            FROM chats c
            JOIN users u1 ON c.user1_id = u1.id
            JOIN users u2 ON c.user2_id = u2.id
            WHERE c.user1_id = %s OR c.user2_id = %s
            ORDER BY CASE WHEN c.last_message_at IS NULL THEN 1 ELSE 0 END, 
                     c.last_message_at DESC
        """
        return self._execute(
            query,
            (user_id, user_id, user_id, user_id, user_id),
            fetch_all=True
        ) or []
    
    def update_chat_timestamp(self, user1_id: int, user2_id: int) -> None:
        query = """
            UPDATE chats 
            SET last_message_at = CURRENT_TIMESTAMP
            WHERE (user1_id = %s AND user2_id = %s)
               OR (user1_id = %s AND user2_id = %s)
        """
        self._execute(query, (user1_id, user2_id, user2_id, user1_id))