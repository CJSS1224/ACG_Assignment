"""
Message Handlers

Handles WebSocket events related to messaging.
"""

from datetime import datetime
from flask_socketio import emit
from flask import request

from src.models.user_model import get_user_by_id
from src.models.message_model import store_message, update_chat_last_message
from src.socket_handlers.connection_manager import (
    get_user_id, get_session_id, is_user_online
)


def handle_send_message(data):
    """
    Handle sending an encrypted message.
    
    Args:
        data: Message data containing:
            - recipient_id: int
            - encrypted_payload: string (Base64)
            - encrypted_key: string (Base64)
            - encrypted_key_sender: string (Base64)
            - iv: string (Base64)
            - signature: string (Base64)
            - hmac: string (Base64)
    """
    session_id = request.sid
    sender_id = get_user_id(session_id)
    
    if not sender_id:
        emit('error', {'message': 'Not authenticated'})
        return
    
    recipient_id = data.get('recipient_id')
    
    if not recipient_id:
        emit('error', {'message': 'Recipient ID required'})
        return
    
    try:
        # Store message in database
        message_id = store_message(
            sender_id=sender_id,
            recipient_id=recipient_id,
            encrypted_payload=data.get('encrypted_payload'),
            encrypted_key=data.get('encrypted_key'),
            iv=data.get('iv'),
            signature=data.get('signature'),
            hmac=data.get('hmac'),
            encrypted_key_sender=data.get('encrypted_key_sender')
        )
        
        # Update chat last message time
        update_chat_last_message(sender_id, recipient_id)
        
        # Get sender info
        sender = get_user_by_id(sender_id)
        
        # Current timestamp
        timestamp = datetime.utcnow().isoformat() + 'Z'
        
        # Send acknowledgement to sender
        emit('message_sent', {
            'message_id': message_id,
            'recipient_id': recipient_id,
            'timestamp': timestamp
        })
        
        # Forward to recipient if online
        if is_user_online(recipient_id):
            emit('new_message', {
                'message_id': message_id,
                'sender_id': sender_id,
                'sender_username': sender['username'] if sender else 'Unknown',
                'sender_public_key': sender['public_key'] if sender else None,
                'encrypted_payload': data.get('encrypted_payload'),
                'encrypted_key': data.get('encrypted_key'),
                'encrypted_key_sender': data.get('encrypted_key_sender'),
                'iv': data.get('iv'),
                'signature': data.get('signature'),
                'hmac': data.get('hmac'),
                'timestamp': timestamp
            }, room=f"user_{recipient_id}")
        
        print(f"[SOCKET] Message from {sender_id} to {recipient_id}")
        
    except Exception as e:
        print(f"[SOCKET] Error storing message: {e}")
        emit('error', {'message': 'Failed to send message'})


def handle_typing(data):
    """Handle typing indicator."""
    session_id = request.sid
    sender_id = get_user_id(session_id)
    
    if not sender_id:
        return
    
    recipient_id = data.get('recipient_id')
    
    if recipient_id and is_user_online(recipient_id):
        emit('user_typing', {
            'user_id': sender_id
        }, room=f"user_{recipient_id}")


def handle_stop_typing(data):
    """Handle stop typing indicator."""
    session_id = request.sid
    sender_id = get_user_id(session_id)
    
    if not sender_id:
        return
    
    recipient_id = data.get('recipient_id')
    
    if recipient_id and is_user_online(recipient_id):
        emit('user_stop_typing', {
            'user_id': sender_id
        }, room=f"user_{recipient_id}")
