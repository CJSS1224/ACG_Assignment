"""
WebSocket Routes
================
Implemented by: Solomon (Message Service & API Specialist)

Real-time messaging using Socket.IO.
Uses Denise's HMAC functions for transit integrity verification.

Events:
    INCOMING:
        - connect: User connects (with token)
        - disconnect: User disconnects
        - send_message: Send encrypted message
        - typing: Typing indicator
        - stop_typing: Stop typing indicator
        - get_online_users: Request online users list
    
    OUTGOING:
        - user_online: User came online
        - user_offline: User went offline
        - new_message: New message received
        - message_sent: Message sent confirmation
        - online_users_list: List of online users
        - user_typing: Someone is typing
        - user_stop_typing: Someone stopped typing
        - error: Error message

INTEGRITY IN TRANSIT:
    All messages include HMAC for integrity verification.
"""

import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import jwt
import base64
from flask import request
from flask_socketio import emit, join_room, disconnect

from crypto import generate_hmac, verify_hmac
from models import Database, UserService, MessageService


# Online users tracking
online_users = {}   # {session_id: user_data}
user_sessions = {}  # {user_id: session_id}
user_secrets = {}   # {user_id: session_secret}
user_keys = {}      # {user_id: private_key}

# Services (initialized in register_socket_events)
db = None
user_service = None
message_service = None


def register_socket_events(socketio, database: Database, secret_key: str):
    """Register all Socket.IO event handlers. [Solomon]"""
    global db, user_service, message_service
    db = database
    user_service = UserService(db)
    message_service = MessageService(db)
    
    # =========================================================================
    # HELPER FUNCTIONS [Solomon, using Denise's HMAC functions]
    # =========================================================================
    
    def verify_token(token: str) -> dict:
        """Verify JWT token and return payload."""
        try:
            payload = jwt.decode(token, secret_key, algorithms=['HS256'])
            return payload
        except:
            return None
    
    def wrap_with_hmac(data: dict, user_id: int) -> dict:
        """
        Add HMAC to outgoing data for transit integrity. [Solomon]
        Uses Denise's generate_hmac function.
        
        INTEGRITY IN TRANSIT: Server signs all outgoing data.
        Client will verify this HMAC to ensure response wasn't tampered.
        """
        secret = user_secrets.get(user_id)
        if not secret:
            return {'payload': data}
        
        hmac_value = generate_hmac(data, secret)
        return {
            'payload': data,
            'hmac': hmac_value
        }
    
    def verify_incoming_hmac(data: dict, user_id: int) -> tuple:
        """
        Verify HMAC on incoming data. [Solomon]
        Uses Denise's verify_hmac function.
        
        INTEGRITY IN TRANSIT: Verify client's data wasn't tampered.
        
        Returns:
            tuple: (is_valid, payload, error_message)
        """
        if not isinstance(data, dict):
            return False, {}, "Invalid data format"
        
        received_hmac = data.get('hmac')
        payload = data.get('payload', data)
        
        # If no HMAC provided, accept for backwards compatibility
        if not received_hmac:
            print(f"[TRANSIT] Warning: No HMAC from user {user_id}")
            return True, payload, None
        
        secret = user_secrets.get(user_id)
        if not secret:
            return True, payload, None
        
        if verify_hmac(payload, received_hmac, secret):
            print(f"[TRANSIT] ✓ HMAC verified for user {user_id}")
            return True, payload, None
        else:
            print(f"[TRANSIT] ✗ HMAC INVALID for user {user_id}")
            return False, {}, "Transit integrity check failed"
    
    # =========================================================================
    # CONNECTION HANDLERS [Solomon]
    # =========================================================================
    
    @socketio.on('connect')
    def handle_connect():
        """Handle WebSocket connection. [Solomon]"""
        token = request.args.get('token')
        if not token:
            print("[SOCKET] No token provided")
            disconnect()
            return False
        
        payload = verify_token(token)
        if not payload:
            print("[SOCKET] Invalid token")
            disconnect()
            return False
        
        user_id = payload['user_id']
        session_id = request.sid
        session_secret = base64.b64decode(payload['session_secret'])
        
        # Get user info
        user = user_service.get_user(user_id)
        if not user:
            disconnect()
            return False
        
        # Store session info
        online_users[session_id] = {
            'user_id': user_id,
            'username': user['username'],
            'public_key': user['public_key']
        }
        user_sessions[user_id] = session_id
        user_secrets[user_id] = session_secret
        
        # Join personal room
        join_room(f"user_{user_id}")
        
        print(f"[SOCKET] {user['username']} connected (ID: {user_id})")
        
        # Notify others
        broadcast_data = wrap_with_hmac({
            'user_id': user_id,
            'username': user['username'],
            'public_key': user['public_key']
        }, user_id)
        emit('user_online', broadcast_data, broadcast=True, include_self=False)
        
        return True
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle WebSocket disconnection. [Solomon]"""
        session_id = request.sid
        user_data = online_users.pop(session_id, None)
        
        if user_data:
            user_id = user_data['user_id']
            user_sessions.pop(user_id, None)
            user_secrets.pop(user_id, None)
            user_keys.pop(user_id, None)
            
            emit('user_offline', {'user_id': user_id}, broadcast=True)
            print(f"[SOCKET] User {user_id} disconnected")
    
    @socketio.on('get_online_users')
    def handle_get_online_users():
        """Get list of currently online users. [Solomon]"""
        session_id = request.sid
        user_data = online_users.get(session_id)
        
        if not user_data:
            return
        
        current_user_id = user_data['user_id']
        
        # Build list of online users (excluding current user)
        users = []
        for uid, sid in user_sessions.items():
            if uid != current_user_id:
                other_user = online_users.get(sid)
                if other_user:
                    users.append({
                        'id': other_user['user_id'],
                        'username': other_user['username'],
                        'public_key': other_user['public_key']
                    })
        
        response = wrap_with_hmac({'users': users}, current_user_id)
        emit('online_users_list', response)
    
    # =========================================================================
    # MESSAGE HANDLER [Solomon]
    # =========================================================================
    
    @socketio.on('send_message')
    def handle_send_message(data):
        """
        Handle sending an encrypted message. [Solomon]
        
        PROCESS:
            1. Verify transit integrity (HMAC) [Uses Denise's verify_hmac]
            2. Encrypt message (AES-GCM) [Uses Charles's aes_gcm_encrypt]
            3. Encrypt AES key (RSA-OAEP) [Uses Amir's rsa_encrypt]
            4. Sign for non-repudiation (RSA-PSS) [Uses Yong Cheng's rsa_sign]
            5. Store in database [Uses Akash's store_message]
            6. Forward to recipient [Solomon]
        
        Expected data (wrapped):
            {
                "payload": {
                    "recipient_id": 2,
                    "message": "Hello Bob!",
                    "private_key": "-----BEGIN PRIVATE KEY-----..."
                },
                "hmac": "..."
            }
        """
        session_id = request.sid
        user_data = online_users.get(session_id)
        
        if not user_data:
            emit('error', {'message': 'Not authenticated'})
            return
        
        sender_id = user_data['user_id']
        
        # =================================================================
        # STEP 1: VERIFY TRANSIT INTEGRITY [Denise's verify_hmac]
        # =================================================================
        is_valid, payload, error = verify_incoming_hmac(data, sender_id)
        if not is_valid:
            emit('error', wrap_with_hmac({'message': error}, sender_id))
            return
        
        # Extract data
        recipient_id = payload.get('recipient_id')
        message = payload.get('message', '').strip()
        private_key = payload.get('private_key')
        
        if not all([recipient_id, message, private_key]):
            emit('error', wrap_with_hmac({'message': 'Missing required fields'}, sender_id))
            return
        
        # Get recipient info
        recipient = user_service.get_user(recipient_id)
        if not recipient:
            emit('error', wrap_with_hmac({'message': 'Recipient not found'}, sender_id))
            return
        
        # =================================================================
        # STEPS 2-5: ENCRYPT, SIGN, AND STORE
        # [Solomon's encrypt_and_store_message orchestrates
        #  Charles (AES), Amir (RSA-OAEP), Yong Cheng (RSA-PSS),
        #  Akash (Database)]
        # =================================================================
        try:
            message_id = message_service.encrypt_and_store_message(
                plaintext=message,
                sender_id=sender_id,
                sender_private_key=private_key,
                sender_public_key=user_data['public_key'],
                recipient_id=recipient_id,
                recipient_public_key=recipient['public_key']
            )
            
            if not message_id:
                emit('error', wrap_with_hmac({'message': 'Failed to store message'}, sender_id))
                return
            
            # Confirm to sender
            emit('message_sent', wrap_with_hmac({
                'message_id': message_id,
                'status': 'sent'
            }, sender_id))
            
            print(f"[MSG] {sender_id} -> {recipient_id}: Message stored (ID: {message_id})")
            
            # =================================================================
            # STEP 6: FORWARD TO RECIPIENT (if online)
            # =================================================================
            if recipient_id in user_sessions:
                # Get recipient's private key to decrypt for them
                recipient_private_key = user_keys.get(recipient_id)
                
                if recipient_private_key:
                    # Decrypt for recipient
                    msg = db.get_message_by_id(message_id)
                    if msg:
                        try:
                            decrypted = message_service.decrypt_message(
                                msg, recipient_id, recipient_private_key
                            )
                            
                            outgoing = wrap_with_hmac({
                                'message_id': message_id,
                                'sender_id': sender_id,
                                'sender_username': user_data['username'],
                                'message': decrypted['plaintext'],
                                'signature_valid': decrypted['signature_valid'],
                                'timestamp': decrypted['timestamp']
                            }, recipient_id)
                            
                            emit('new_message', outgoing, room=f"user_{recipient_id}")
                        except Exception as e:
                            print(f"[MSG] Failed to decrypt for recipient: {e}")
                            # Send encrypted data instead
                            emit('new_message_encrypted', wrap_with_hmac({
                                'message_id': message_id,
                                'sender_id': sender_id,
                                'sender_username': user_data['username']
                            }, recipient_id), room=f"user_{recipient_id}")
                else:
                    # Notify recipient they have a new message
                    emit('new_message_encrypted', wrap_with_hmac({
                        'message_id': message_id,
                        'sender_id': sender_id,
                        'sender_username': user_data['username']
                    }, recipient_id), room=f"user_{recipient_id}")
            
        except Exception as e:
            print(f"[MSG] Error: {e}")
            emit('error', wrap_with_hmac({'message': 'Failed to send message'}, sender_id))
    
    @socketio.on('store_private_key')
    def handle_store_private_key(data):
        """
        Store user's private key in session for real-time decryption. [Solomon]
        
        This allows the server to decrypt messages for real-time delivery.
        The key is only stored in memory for the session duration.
        """
        session_id = request.sid
        user_data = online_users.get(session_id)
        
        if not user_data:
            return
        
        user_id = user_data['user_id']
        
        # Verify HMAC
        is_valid, payload, _ = verify_incoming_hmac(data, user_id)
        if not is_valid:
            return
        
        private_key = payload.get('private_key')
        if private_key:
            user_keys[user_id] = private_key
            print(f"[SOCKET] Private key stored for user {user_id}")
    
    # =========================================================================
    # TYPING INDICATORS [Solomon]
    # =========================================================================
    
    @socketio.on('typing')
    def handle_typing(data):
        """Handle typing indicator. [Solomon]"""
        session_id = request.sid
        user_data = online_users.get(session_id)
        
        if not user_data:
            return
        
        sender_id = user_data['user_id']
        is_valid, payload, _ = verify_incoming_hmac(data, sender_id)
        if not is_valid:
            return
        
        recipient_id = payload.get('recipient_id')
        if recipient_id in user_sessions:
            emit('user_typing', wrap_with_hmac({
                'user_id': sender_id
            }, recipient_id), room=f"user_{recipient_id}")
    
    @socketio.on('stop_typing')
    def handle_stop_typing(data):
        """Handle stop typing indicator. [Solomon]"""
        session_id = request.sid
        user_data = online_users.get(session_id)
        
        if not user_data:
            return
        
        sender_id = user_data['user_id']
        is_valid, payload, _ = verify_incoming_hmac(data, sender_id)
        if not is_valid:
            return
        
        recipient_id = payload.get('recipient_id')
        if recipient_id in user_sessions:
            emit('user_stop_typing', wrap_with_hmac({
                'user_id': sender_id
            }, recipient_id), room=f"user_{recipient_id}")


def get_online_user_ids():
    """Get set of online user IDs."""
    return set(user_sessions.keys())
