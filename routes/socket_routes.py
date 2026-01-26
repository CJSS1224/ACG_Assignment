"""
Socket Routes - ST2504 Applied Cryptography

WebSocket event handlers:
- connect/disconnect - Connection management (Solomon)
- send_message - Message sending with encryption (Charles, Amir, Yong Cheng, Denise)
- typing indicators - Real-time status (Solomon)
"""

from flask import request
from flask_socketio import emit, join_room, disconnect
from models.auth_model import AuthModel
from models.database_model import DatabaseModel
from models.connection_model import ConnectionModel
from controllers.message_controller import MessageController


# Initialize models and controllers
auth_model = AuthModel()
db = DatabaseModel()
connections = ConnectionModel()
message_controller = MessageController()


def register_socket_events(socketio):
    """Register all WebSocket event handlers."""
    
    @socketio.on('connect')
    def handle_connect():
        """Handle WebSocket connection."""
        token = request.args.get('token')
        
        if not token:
            print("[SOCKET] Connection rejected: No token")
            disconnect()
            return False
        
        payload = auth_model.verify_token(token)
        if not payload:
            print("[SOCKET] Connection rejected: Invalid token")
            disconnect()
            return False
        
        user_id = payload['id']
        username = payload['username']
        session_id = request.sid
        
        # Add connection
        connections.add_connection(session_id, user_id)
        join_room(f"user_{user_id}")
        
        print(f"[SOCKET] User {username} (ID: {user_id}) connected")
        
        # Broadcast online status
        emit('user_online', {
            'user_id': user_id,
            'username': username
        }, broadcast=True, include_self=False)
        
        return True
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle WebSocket disconnection."""
        session_id = request.sid
        
        user_id = connections.remove_connection(session_id)
        if user_id:
            user = db.get_user_by_id(user_id)
            username = user['username'] if user else 'Unknown'
            
            print(f"[SOCKET] User {username} (ID: {user_id}) disconnected")
            
            emit('user_offline', {
                'user_id': user_id,
                'username': username
            }, broadcast=True)
    
    @socketio.on('get_online_users')
    def handle_get_online_users():
        """Get list of online users via WebSocket."""
        session_id = request.sid
        
        if not connections.is_session_valid(session_id):
            emit('error', {'message': 'Not authenticated'})
            return
        
        current_user_id = connections.get_user_id(session_id)
        online_user_ids = connections.get_online_user_ids(exclude_user_id=current_user_id)
        
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
    
    @socketio.on('send_message')
    def handle_send_message(data):
        """
        Handle sending a message with server-side encryption.
        
        Security Model (all crypto in Python):
        - AES-256-CTR encryption for confidentiality (Charles)
        - RSA-OAEP for key exchange (Denise)
        - RSA signatures for non-repudiation (Yong Cheng)
        - HMAC-SHA256 for integrity (Amir)
        """
        session_id = request.sid
        
        if not connections.is_session_valid(session_id):
            emit('error', {'message': 'Not authenticated'})
            return
        
        sender_id = connections.get_user_id(session_id)
        recipient_id = data.get('recipient_id')
        plaintext = data.get('plaintext', '').strip()
        sender_private_key = data.get('private_key')
        
        # Send message using controller
        result = message_controller.send_message(
            sender_id=sender_id,
            recipient_id=recipient_id,
            plaintext=plaintext,
            sender_private_key=sender_private_key
        )
        
        if 'error' in result:
            emit('error', {'message': result['error']})
            return
        
        # Confirm to sender
        emit('message_sent', {'message_id': result['message_id']})
        
        # Forward to recipient if online
        if connections.is_user_online(recipient_id):
            emit('new_message', {
                'message_id': result['message_id'],
                'sender_id': sender_id,
                'sender_username': result['sender']['username'],
                'plaintext': result['plaintext'],
                'timestamp': None
            }, room=f"user_{recipient_id}")
    
    @socketio.on('typing')
    def handle_typing(data):
        """Handle typing indicator."""
        session_id = request.sid
        if not connections.is_session_valid(session_id):
            return
        
        user_id = connections.get_user_id(session_id)
        recipient_id = data.get('recipient_id')
        
        if connections.is_user_online(recipient_id):
            emit('user_typing', {'user_id': user_id}, room=f"user_{recipient_id}")
    
    @socketio.on('stop_typing')
    def handle_stop_typing(data):
        """Handle stop typing indicator."""
        session_id = request.sid
        if not connections.is_session_valid(session_id):
            return
        
        user_id = connections.get_user_id(session_id)
        recipient_id = data.get('recipient_id')
        
        if connections.is_user_online(recipient_id):
            emit('user_stop_typing', {'user_id': user_id}, room=f"user_{recipient_id}")
