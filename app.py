"""
ST2504 Applied Cryptography - SecureChat Application
Main Flask Application

This is the main entry point for the SecureChat application.
All cryptographic operations are performed in Python:
- AES-256-CTR for message encryption (Member 3)
- HMAC-SHA256 for integrity (Member 4)
- RSA signatures for non-repudiation (Member 5)
- RSA key management (Member 6)

Team Members:
- Solomon: Server & Authentication
- Charles: Client Interface  
- Charles: AES Encryption
- Amir: HMAC Integrity
- Yong Cheng: Digital Signatures
- Denise: Key Management
- Akash: Database & Message Storage
"""

import os
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit, join_room, disconnect
from flask_cors import CORS
from dotenv import load_dotenv

# Import services
from services.auth_service import AuthService
from services.crypto_service import CryptoService
from services.database_service import DatabaseService

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__, 
    template_folder='templates',
    static_folder='static',
    static_url_path='/static'
)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

# Initialize extensions
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize services
db = DatabaseService()
auth = AuthService(db)
crypto = CryptoService()

# =============================================================================
# IN-MEMORY CONNECTION TRACKING
# =============================================================================

active_connections = {}  # {session_id: user_id}
user_sessions = {}       # {user_id: session_id}


# =============================================================================
# HTTP ROUTES - PAGES
# =============================================================================

@app.route('/')
def index():
    """Serve the main chat interface."""
    return render_template('index.html')


# =============================================================================
# HTTP ROUTES - AUTHENTICATION (Member 1)
# =============================================================================

@app.route('/api/register', methods=['POST'])
def register():
    """Register a new user with RSA keypair generation."""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    if not password or len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    
    if db.get_user_by_username(username):
        return jsonify({'error': 'Username already exists'}), 400
    
    # Generate RSA keypair (Member 6)
    private_key_pem, public_key_pem = crypto.generate_rsa_keypair()
    
    # Hash password and create user (Member 1)
    password_hash = auth.hash_password(password)
    user_id = db.create_user(username, password_hash, public_key_pem)
    
    if not user_id:
        return jsonify({'error': 'Failed to create user'}), 500
    
    token = auth.generate_token(user_id, username)
    
    return jsonify({
        'token': token,
        'user_id': user_id,
        'username': username,
        'public_key': public_key_pem,
        'private_key': private_key_pem
    }), 201


@app.route('/api/login', methods=['POST'])
def login():
    """Authenticate a user."""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    user = db.get_user_by_username(username)
    if not user:
        return jsonify({'error': 'Invalid username or password'}), 401
    
    if not auth.verify_password(password, user['password_hash']):
        return jsonify({'error': 'Invalid username or password'}), 401
    
    db.update_last_login(user['id'])
    token = auth.generate_token(user['id'], user['username'])
    
    return jsonify({
        'token': token,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'public_key': user['public_key']
        }
    }), 200


@app.route('/api/me', methods=['GET'])
def get_current_user():
    """Get current user info."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    payload = auth.verify_token(token)
    
    if not payload:
        return jsonify({'error': 'Invalid token'}), 401
    
    user = db.get_user_by_id(payload['id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'public_key': user['public_key']
    }), 200


# =============================================================================
# HTTP ROUTES - USERS (Member 1)
# =============================================================================

@app.route('/api/users/online', methods=['GET'])
def get_online_users():
    """Get list of currently online users."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    payload = auth.verify_token(token)
    
    if not payload:
        return jsonify({'error': 'Invalid token'}), 401
    
    current_user_id = payload['id']
    online_user_ids = set(active_connections.values())
    online_user_ids.discard(current_user_id)
    
    users = []
    for uid in online_user_ids:
        user = db.get_user_by_id(uid)
        if user:
            users.append({
                'id': user['id'],
                'username': user['username'],
                'public_key': user['public_key']
            })
    
    return jsonify(users), 200


@app.route('/api/users/<int:user_id>/public-key', methods=['GET'])
def get_user_public_key(user_id):
    """Get a user's public key."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    payload = auth.verify_token(token)
    
    if not payload:
        return jsonify({'error': 'Invalid token'}), 401
    
    user = db.get_user_by_id(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'user_id': user['id'],
        'username': user['username'],
        'public_key': user['public_key']
    }), 200


# =============================================================================
# HTTP ROUTES - CHATS (Member 1)
# =============================================================================

@app.route('/api/chats', methods=['GET'])
def get_chats():
    """Get all chats for current user."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    payload = auth.verify_token(token)
    
    if not payload:
        return jsonify({'error': 'Invalid token'}), 401
    
    chats = db.get_user_chats(payload['id'])
    print(f"[API] get_chats for user {payload['id']}: found {len(chats) if chats else 0} chats")
    if chats:
        for c in chats:
            print(f"[API]   - Chat {c.get('chat_id')} with user {c.get('other_user_id')} ({c.get('other_username')})")
    return jsonify(chats or []), 200


@app.route('/api/chats', methods=['POST'])
def create_chat():
    """Create or get existing chat with another user."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    payload = auth.verify_token(token)
    
    if not payload:
        return jsonify({'error': 'Invalid token'}), 401
    
    data = request.get_json()
    other_user_id = data.get('user_id')
    
    if not other_user_id:
        return jsonify({'error': 'user_id required'}), 400
    
    other_user = db.get_user_by_id(other_user_id)
    if not other_user:
        return jsonify({'error': 'User not found'}), 404
    
    chat_id = db.get_or_create_chat(payload['id'], other_user_id)
    
    return jsonify({
        'chat_id': chat_id,
        'other_user': {
            'id': other_user['id'],
            'username': other_user['username'],
            'public_key': other_user['public_key']
        }
    }), 200


@app.route('/api/chats/<int:other_user_id>/messages', methods=['POST'])
def get_chat_messages(other_user_id):
    """
    Get and decrypt messages for a chat.
    
    Client provides their private key in request body for decryption.
    Server decrypts messages using Python crypto (Member 3).
    """
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    payload = auth.verify_token(token)
    
    if not payload:
        return jsonify({'error': 'Invalid token'}), 401
    
    current_user_id = payload['id']
    data = request.get_json() or {}
    private_key = data.get('private_key')
    
    # Get encrypted messages from database
    messages = db.get_chat_messages(current_user_id, other_user_id)
    
    result_messages = []
    for msg in messages:
        try:
            if private_key:
                # Get sender's public key for signature verification
                sender_public_key = None
                if msg['sender_id'] != current_user_id:
                    sender = db.get_user_by_id(msg['sender_id'])
                    sender_public_key = sender['public_key'] if sender else None
                
                # Decrypt message using Python crypto (Member 3)
                decrypted = crypto.decrypt_message(
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
                # No private key - return encrypted data
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
    
    return jsonify(result_messages), 200


# =============================================================================
# WEBSOCKET EVENTS - CONNECTION (Member 1)
# =============================================================================

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection."""
    token = request.args.get('token')
    
    if not token:
        print("[SOCKET] Connection rejected: No token")
        disconnect()
        return False
    
    payload = auth.verify_token(token)
    if not payload:
        print("[SOCKET] Connection rejected: Invalid token")
        disconnect()
        return False
    
    user_id = payload['id']
    username = payload['username']
    session_id = request.sid
    
    active_connections[session_id] = user_id
    user_sessions[user_id] = session_id
    join_room(f"user_{user_id}")
    
    print(f"[SOCKET] User {username} (ID: {user_id}) connected")
    
    emit('user_online', {
        'user_id': user_id,
        'username': username
    }, broadcast=True, include_self=False)
    
    return True


@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection."""
    session_id = request.sid
    
    if session_id in active_connections:
        user_id = active_connections[session_id]
        user = db.get_user_by_id(user_id)
        username = user['username'] if user else 'Unknown'
        
        del active_connections[session_id]
        if user_id in user_sessions:
            del user_sessions[user_id]
        
        print(f"[SOCKET] User {username} (ID: {user_id}) disconnected")
        
        emit('user_offline', {
            'user_id': user_id,
            'username': username
        }, broadcast=True)


@socketio.on('get_online_users')
def handle_get_online_users():
    """Get list of online users via WebSocket."""
    session_id = request.sid
    
    if session_id not in active_connections:
        emit('error', {'message': 'Not authenticated'})
        return
    
    current_user_id = active_connections[session_id]
    online_user_ids = set(active_connections.values())
    online_user_ids.discard(current_user_id)
    
    users = []
    for uid in online_user_ids:
        user = db.get_user_by_id(uid)
        if user:
            users.append({
                'id': user['id'],
                'username': user['username'],
                'public_key': user['public_key']
            })
    
    emit('online_users_list', {'users': users})


# =============================================================================
# WEBSOCKET EVENTS - MESSAGING (Member 1, 3, 4, 5, 6)
# =============================================================================

@socketio.on('send_message')
def handle_send_message(data):
    """
    Handle sending a message with server-side encryption.
    
    Security Model (all crypto in Python):
    - AES-256-CTR encryption for confidentiality (Member 3)
    - RSA-OAEP for key exchange (Member 6)
    - RSA signatures for non-repudiation (Member 5)
    - HMAC-SHA256 for integrity (Member 4)
    
    At-rest: Messages stored encrypted in database
    In-transit: Plaintext sent to recipient for real-time display (use HTTPS)
    """
    session_id = request.sid
    
    if session_id not in active_connections:
        emit('error', {'message': 'Not authenticated'})
        return
    
    sender_id = active_connections[session_id]
    recipient_id = data.get('recipient_id')
    plaintext = data.get('plaintext', '').strip()
    sender_private_key = data.get('private_key')
    
    if not recipient_id:
        emit('error', {'message': 'Recipient ID required'})
        return
    
    if not plaintext:
        emit('error', {'message': 'Message cannot be empty'})
        return
    
    if not sender_private_key:
        emit('error', {'message': 'Private key required for signing'})
        return
    
    # Get sender and recipient info
    sender = db.get_user_by_id(sender_id)
    recipient = db.get_user_by_id(recipient_id)
    
    if not sender or not recipient:
        emit('error', {'message': 'User not found'})
        return
    
    try:
        # =================================================================
        # SERVER-SIDE ENCRYPTION (All cryptography in Python)
        # =================================================================
        
        # Encrypt message using crypto service
        # This performs: AES encryption, RSA key exchange, signing, HMAC
        encrypted_data = crypto.encrypt_message(
            plaintext=plaintext,
            recipient_public_key=recipient['public_key'],
            sender_private_key=sender_private_key,
            sender_public_key=sender['public_key']
        )
        
        # Store encrypted message in database (at-rest encryption)
        message_id = db.store_message(
            sender_id=sender_id,
            recipient_id=recipient_id,
            encrypted_payload=encrypted_data['encrypted_payload'],
            encrypted_key=encrypted_data['encrypted_key'],
            encrypted_key_sender=encrypted_data['encrypted_key_sender'],
            iv=encrypted_data['iv'],
            signature=encrypted_data['signature'],
            hmac=encrypted_data['hmac']
        )
        
        db.update_chat_timestamp(sender_id, recipient_id)
        
        # Confirm to sender
        emit('message_sent', {'message_id': message_id})
        
        # Forward to recipient if online
        if recipient_id in user_sessions:
            emit('new_message', {
                'message_id': message_id,
                'sender_id': sender_id,
                'sender_username': sender['username'],
                'plaintext': plaintext,
                'timestamp': None
            }, room=f"user_{recipient_id}")
            
    except Exception as e:
        print(f"[ERROR] Failed to encrypt/store message: {e}")
        import traceback
        traceback.print_exc()
        emit('error', {'message': 'Failed to send message'})


@socketio.on('typing')
def handle_typing(data):
    """Handle typing indicator."""
    session_id = request.sid
    if session_id not in active_connections:
        return
    
    user_id = active_connections[session_id]
    recipient_id = data.get('recipient_id')
    
    if recipient_id in user_sessions:
        emit('user_typing', {'user_id': user_id}, room=f"user_{recipient_id}")


@socketio.on('stop_typing')
def handle_stop_typing(data):
    """Handle stop typing indicator."""
    session_id = request.sid
    if session_id not in active_connections:
        return
    
    user_id = active_connections[session_id]
    recipient_id = data.get('recipient_id')
    
    if recipient_id in user_sessions:
        emit('user_stop_typing', {'user_id': user_id}, room=f"user_{recipient_id}")


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("ST2504 Applied Cryptography - SecureChat Server")
    print("=" * 60)
    print("Starting server on http://localhost:5000")
    print("Press Ctrl+C to stop")
    print("=" * 60)
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
