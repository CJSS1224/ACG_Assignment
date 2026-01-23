"""
ST2504 Applied Cryptography - Secure Messaging Web Application

Main Flask application entry point.
Routes and socket handlers are organized in separate modules.

Security Features:
- Password hashing with bcrypt
- JWT token authentication
- End-to-end encryption (AES-256)
- Message integrity (HMAC-SHA256)
- Non-repudiation (RSA digital signatures)
"""

import os
import sys
from flask import Flask, send_from_directory, jsonify
from flask_socketio import SocketIO
from flask_cors import CORS
from dotenv import load_dotenv

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key')

# Enable CORS
CORS(app)

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')


# =============================================================================
# REGISTER BLUEPRINTS (Routes)
# =============================================================================

from src.routes import auth_bp, user_bp, chat_bp

app.register_blueprint(auth_bp)
app.register_blueprint(user_bp)
app.register_blueprint(chat_bp)


# =============================================================================
# STATIC FILE ROUTES
# =============================================================================

@app.route('/')
def index():
    """Serve the main page."""
    return send_from_directory('templates', 'index.html')


@app.route('/<path:filename>')
def serve_static(filename):
    """Serve static files."""
    if filename.endswith('.html'):
        return send_from_directory('templates', filename)
    return send_from_directory('static', filename)


# =============================================================================
# WEBSOCKET EVENTS
# =============================================================================

from src.socket_handlers import (
    handle_connect, handle_disconnect, handle_get_online_users,
    handle_send_message, handle_typing, handle_stop_typing
)

@socketio.on('connect')
def on_connect():
    return handle_connect()

@socketio.on('disconnect')
def on_disconnect():
    handle_disconnect()

@socketio.on('send_message')
def on_send_message(data):
    handle_send_message(data)

@socketio.on('typing')
def on_typing(data):
    handle_typing(data)

@socketio.on('stop_typing')
def on_stop_typing(data):
    handle_stop_typing(data)

@socketio.on('get_online_users')
def on_get_online_users():
    handle_get_online_users()


# =============================================================================
# ERROR HANDLERS
# =============================================================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500


# =============================================================================
# MAIN
# =============================================================================

if __name__ == '__main__':
    from src.database import init_db
    
    print("\n" + "=" * 60)
    print(" ST2504 Applied Cryptography - Secure Messaging Server")
    print("=" * 60)
    
    # Initialize database
    print("\n[SERVER] Initializing database connection...")
    if not init_db():
        print("[SERVER] WARNING: Database connection failed!")
        print("[SERVER] Make sure MySQL is running and .env is configured")
    
    # Get configuration
    host = os.getenv('SERVER_HOST', '127.0.0.1')
    port = int(os.getenv('SERVER_PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    print(f"\n[SERVER] Starting on http://{host}:{port}")
    print("[SERVER] Press Ctrl+C to stop\n")
    
    # Run with SocketIO
    socketio.run(app, host=host, port=port, debug=debug)
