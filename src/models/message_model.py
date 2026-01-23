"""
Message Model

Handles all database operations related to messages including
storing encrypted messages and retrieving chat history.
"""

from src.database import execute_query


def store_message(sender_id, recipient_id, encrypted_payload, encrypted_key, iv, signature, hmac, encrypted_key_sender=None):
    """
    Store an encrypted message in the database.
    
    Args:
        sender_id: ID of the sender
        recipient_id: ID of the recipient
        encrypted_payload: AES encrypted message (Base64)
        encrypted_key: RSA encrypted AES key for recipient (Base64)
        iv: Initialization vector (Base64)
        signature: RSA digital signature (Base64)
        hmac: HMAC for integrity (Base64)
        encrypted_key_sender: RSA encrypted AES key for sender (Base64) - allows sender to read own messages
        
    Returns:
        Message ID
    """
    query = """
        INSERT INTO messages 
        (sender_id, recipient_id, encrypted_payload, encrypted_key, encrypted_key_sender, iv, signature, hmac)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """
    return execute_query(query, (
        sender_id, recipient_id, encrypted_payload, 
        encrypted_key, encrypted_key_sender, iv, signature, hmac
    ))


def get_messages_between_users(user1_id, user2_id, limit=50):
    """
    Get messages between two users.
    
    Args:
        user1_id: First user ID
        user2_id: Second user ID
        limit: Maximum number of messages to return
        
    Returns:
        List of message dicts with sender info
    """
    query = """
        SELECT 
            m.id,
            m.sender_id,
            m.recipient_id,
            m.encrypted_payload,
            m.encrypted_key,
            m.encrypted_key_sender,
            m.iv,
            m.signature,
            m.hmac,
            m.timestamp,
            m.is_read,
            u.username as sender_username,
            u.public_key as sender_public_key
        FROM messages m
        INNER JOIN users u ON m.sender_id = u.id
        WHERE (m.sender_id = %s AND m.recipient_id = %s)
           OR (m.sender_id = %s AND m.recipient_id = %s)
        ORDER BY m.timestamp ASC
        LIMIT %s
    """
    return execute_query(query, (user1_id, user2_id, user2_id, user1_id, limit), fetch_all=True)


def mark_messages_as_read(recipient_id, sender_id):
    """
    Mark all messages from sender to recipient as read.
    
    Args:
        recipient_id: ID of the recipient
        sender_id: ID of the sender
    """
    query = """
        UPDATE messages
        SET is_read = TRUE
        WHERE recipient_id = %s AND sender_id = %s AND is_read = FALSE
    """
    execute_query(query, (recipient_id, sender_id))


def get_unread_count(user_id):
    """
    Get count of unread messages for a user.
    
    Args:
        user_id: User ID
        
    Returns:
        Dict with sender_id and unread count
    """
    query = """
        SELECT sender_id, COUNT(*) as unread_count
        FROM messages
        WHERE recipient_id = %s AND is_read = FALSE
        GROUP BY sender_id
    """
    return execute_query(query, (user_id,), fetch_all=True)


def get_message_by_id(message_id):
    """
    Get a specific message by ID.
    
    Args:
        message_id: Message ID
        
    Returns:
        Message dict or None
    """
    query = """
        SELECT 
            m.*,
            u.username as sender_username,
            u.public_key as sender_public_key
        FROM messages m
        INNER JOIN users u ON m.sender_id = u.id
        WHERE m.id = %s
    """
    return execute_query(query, (message_id,), fetch_one=True)


# Chat management
def get_or_create_chat(user1_id, user2_id):
    """
    Get existing chat or create a new one between two users.
    
    Args:
        user1_id: First user ID
        user2_id: Second user ID
        
    Returns:
        Chat ID
    """
    # Ensure consistent ordering
    if user1_id > user2_id:
        user1_id, user2_id = user2_id, user1_id
    
    # Check if chat exists
    query = """
        SELECT id FROM chats
        WHERE (user1_id = %s AND user2_id = %s)
           OR (user1_id = %s AND user2_id = %s)
        LIMIT 1
    """
    result = execute_query(query, (user1_id, user2_id, user2_id, user1_id), fetch_one=True)
    
    if result:
        return result['id']
    
    # Create new chat
    insert_query = """
        INSERT INTO chats (user1_id, user2_id)
        VALUES (%s, %s)
    """
    return execute_query(insert_query, (user1_id, user2_id))


def update_chat_last_message(user1_id, user2_id):
    """
    Update the last_message_at timestamp for a chat.
    
    Args:
        user1_id: First user ID
        user2_id: Second user ID
    """
    query = """
        UPDATE chats
        SET last_message_at = CURRENT_TIMESTAMP
        WHERE (user1_id = %s AND user2_id = %s)
           OR (user1_id = %s AND user2_id = %s)
    """
    execute_query(query, (user1_id, user2_id, user2_id, user1_id))


def get_user_chats(user_id):
    """
    Get all chats for a user with the other user's info.
    
    Args:
        user_id: User ID
        
    Returns:
        List of chat dicts with other user info
    """
    query = """
        SELECT 
            c.id as chat_id,
            c.last_message_at,
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
            END as other_public_key
        FROM chats c
        INNER JOIN users u1 ON c.user1_id = u1.id
        INNER JOIN users u2 ON c.user2_id = u2.id
        WHERE c.user1_id = %s OR c.user2_id = %s
        ORDER BY c.last_message_at DESC
    """
    return execute_query(query, (user_id, user_id, user_id, user_id, user_id), fetch_all=True)


def delete_chat(chat_id, user_id):
    """
    Delete a chat (only if user is participant).
    
    Args:
        chat_id: Chat ID
        user_id: User ID (must be participant)
        
    Returns:
        True if deleted, False if not authorized
    """
    # Verify user is part of this chat
    verify_query = """
        SELECT id FROM chats
        WHERE id = %s AND (user1_id = %s OR user2_id = %s)
    """
    result = execute_query(verify_query, (chat_id, user_id, user_id), fetch_one=True)
    
    if not result:
        return False
    
    # Delete the chat (messages will cascade)
    delete_query = "DELETE FROM chats WHERE id = %s"
    execute_query(delete_query, (chat_id,))
    return True
