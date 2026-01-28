"""
Socket Routes - ST2504 Applied Cryptography
============================================

WebSocket event handlers:
- Connection management (Solomon)
- Diffie-Hellman key exchange (Team) - NEW
- Message sending with encryption (Charles, Amir, Yong Cheng, Denise)
"""

from flask import request
from flask_socketio import emit, join_room, disconnect
from models.auth_model import AuthModel
from models.crypto_model import CryptoModel
from models.database_model import DatabaseModel

# Initialize
auth = AuthModel()
crypto = CryptoModel()
db = DatabaseModel()

# Online users tracking
online_users = {}   # {session_id: user_id}
user_sessions = {}  # {user_id: session_id}

# Diffie-Hellman key storage
dh_keys = {}        # {user_id: {'private': int, 'public': str}}
dh_shared = {}      # {(user1_id, user2_id): shared_secret_bytes}


def register_socket_events(socketio):
    """Register all WebSocket event handlers."""
    
    @socketio.on('connect')
    def handle_connect():
        """Handle WebSocket connection."""
        token = request.args.get('token')
        if not token:
            disconnect()
            return False
        
        payload = auth.verify_token(token)
        if not payload:
            disconnect()
            return False
        
        user_id = payload['id']
        session_id = request.sid
        
        # Track online user
        online_users[session_id] = user_id
        user_sessions[user_id] = session_id
        join_room(f"user_{user_id}")
        
        # Generate DH keypair for this session
        dh_private, dh_public = crypto.generate_dh_keypair()
        dh_keys[user_id] = {'private': dh_private, 'public': dh_public}
        
        # Get user's RSA public key for broadcast
        user = db.get_user_by_id(user_id)
        public_key = user['public_key'] if user else None
        
        print(f"[SOCKET] {payload['username']} connected (DH key generated)")
        
        # Broadcast online status with RSA and DH public keys
        emit('user_online', {
            'user_id': user_id,
            'username': payload['username'],
            'public_key': public_key,
            'dh_public_key': dh_public
        }, broadcast=True, include_self=False)
        
        return True
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle WebSocket disconnection."""
        session_id = request.sid
        user_id = online_users.pop(session_id, None)
        
        if user_id:
            user_sessions.pop(user_id, None)
            dh_keys.pop(user_id, None)
            
            # Clean up shared secrets involving this user
            keys_to_remove = [k for k in dh_shared.keys() if user_id in k]
            for k in keys_to_remove:
                dh_shared.pop(k, None)
            
            emit('user_offline', {'user_id': user_id}, broadcast=True)
            print(f"[SOCKET] User {user_id} disconnected")
    
    @socketio.on('get_online_users')
    def handle_get_online_users():
        """Get list of online users with their DH public keys."""
        session_id = request.sid
        current_user_id = online_users.get(session_id)
        
        if not current_user_id:
            return
        
        users = []
        for user_id in user_sessions.keys():
            if user_id != current_user_id:
                user = db.get_user_by_id(user_id)
                if user:
                    user_data = {
                        'id': user['id'],
                        'username': user['username'],
                        'public_key': user['public_key']
                    }
                    # Include DH public key if available
                    if user_id in dh_keys:
                        user_data['dh_public_key'] = dh_keys[user_id]['public']
                    users.append(user_data)
        
        emit('online_users_list', {'users': users})
    
    @socketio.on('dh_exchange')
    def handle_dh_exchange(data):
        """
        Handle Diffie-Hellman key exchange.
        Establishes a shared secret between two users.
        
        This provides FORWARD SECRECY - even if RSA keys are compromised,
        past messages encrypted with DH-derived keys remain secure.
        """
        session_id = request.sid
        sender_id = online_users.get(session_id)
        recipient_id = data.get('recipient_id')
        their_dh_public = data.get('dh_public_key')
        
        if not sender_id or not recipient_id or not their_dh_public:
            return
        
        # Get my DH private key
        my_dh = dh_keys.get(sender_id)
        if not my_dh:
            emit('error', {'message': 'DH key not found'})
            return
        
        try:
            # Compute shared secret
            shared_secret = crypto.compute_dh_shared_secret(my_dh['private'], their_dh_public)
            
            # Store shared secret (sorted tuple key ensures both users access same secret)
            key = tuple(sorted([sender_id, recipient_id]))
            dh_shared[key] = shared_secret
            
            print(f"[DH] Shared secret established: {sender_id} <-> {recipient_id}")
            
            # Notify sender
            emit('dh_complete', {
                'recipient_id': recipient_id,
                'status': 'success'
            })
            
        except Exception as e:
            print(f"[DH] Exchange failed: {e}")
            emit('error', {'message': 'DH exchange failed'})
    
    @socketio.on('send_message')
    def handle_send_message(data):
        """
        Handle sending an encrypted message.
        
        Security (all crypto in Python):
        - AES-256-CTR encryption (Charles)
        - Diffie-Hellman OR RSA-OAEP key exchange (Team/Denise)
        - RSA signatures (Yong Cheng)
        - HMAC-SHA256 integrity (Amir)
        """
        session_id = request.sid
        sender_id = online_users.get(session_id)
        
        if not sender_id:
            emit('error', {'message': 'Not authenticated'})
            return
        
        recipient_id = data.get('recipient_id')
        plaintext = data.get('plaintext', '').strip()
        sender_private_key = data.get('private_key')
        
        if not all([recipient_id, plaintext, sender_private_key]):
            emit('error', {'message': 'Missing required fields'})
            return
        
        # Get users
        sender = db.get_user_by_id(sender_id)
        recipient = db.get_user_by_id(recipient_id)
        
        if not sender or not recipient:
            emit('error', {'message': 'User not found'})
            return
        
        try:
            # Check if we have a DH shared secret
            key = tuple(sorted([sender_id, recipient_id]))
            shared_secret = dh_shared.get(key)
            
            # Encrypt message (uses DH if available, otherwise RSA)
            encrypted = crypto.encrypt_message(
                plaintext=plaintext,
                recipient_public_key=recipient['public_key'],
                sender_private_key=sender_private_key,
                sender_public_key=sender['public_key'],
                dh_shared_secret=shared_secret
            )
            
            # Store in database (Akash)
            message_id = db.store_message(
                sender_id=sender_id,
                recipient_id=recipient_id,
                encrypted_payload=encrypted['encrypted_payload'],
                encrypted_key=encrypted['encrypted_key'],
                encrypted_key_sender=encrypted['encrypted_key_sender'],
                iv=encrypted['iv'],
                signature=encrypted['signature'],
                hmac=encrypted['hmac']
            )
            
            # Ensure chat exists
            db.get_or_create_chat(sender_id, recipient_id)
            db.update_chat_timestamp(sender_id, recipient_id)
            
            # Confirm to sender with key exchange method
            emit('message_sent', {
                'message_id': message_id,
                'key_exchange': encrypted['key_exchange']
            })
            
            # Forward to recipient if online
            if recipient_id in user_sessions:
                emit('new_message', {
                    'message_id': message_id,
                    'sender_id': sender_id,
                    'sender_username': sender['username'],
                    'sender_public_key': sender['public_key'],
                    'encrypted_payload': encrypted['encrypted_payload'],
                    'encrypted_key': encrypted['encrypted_key'],
                    'iv': encrypted['iv'],
                    'signature': encrypted['signature'],
                    'key_exchange': encrypted['key_exchange']
                }, room=f"user_{recipient_id}")
            
            print(f"[MSG] {sender_id} -> {recipient_id} (Key: {encrypted['key_exchange']})")
            
        except Exception as e:
            print(f"[ERROR] Message failed: {e}")
            emit('error', {'message': 'Failed to send message'})
    
    @socketio.on('typing')
    def handle_typing(data):
        """Handle typing indicator."""
        session_id = request.sid
        sender_id = online_users.get(session_id)
        recipient_id = data.get('recipient_id')
        
        if sender_id and recipient_id in user_sessions:
            emit('user_typing', {'user_id': sender_id}, room=f"user_{recipient_id}")
    
    @socketio.on('stop_typing')
    def handle_stop_typing(data):
        """Handle stop typing."""
        session_id = request.sid
        sender_id = online_users.get(session_id)
        recipient_id = data.get('recipient_id')
        
        if sender_id and recipient_id in user_sessions:
            emit('user_stop_typing', {'user_id': sender_id}, room=f"user_{recipient_id}")


def get_online_user_ids():
    """Get set of online user IDs (for API route)."""
    return set(user_sessions.keys())
