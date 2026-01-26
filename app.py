"""
ST2504 Applied Cryptography - SecureChat Application
Main Entry Point

This is the main entry point that initializes the Flask app and registers routes.
The application follows the MVC pattern:
- Routes: Define API endpoints
- Controllers: Handle business logic
- Middleware: Authentication and validation
- Models: Database operations and services

Team Members:
- Solomon: Server & Authentication
- Charles: Client Interface & AES Encryption
- Amir: HMAC Integrity
- Yong Cheng: Digital Signatures
- Denise: Key Management
- Akash: Database & Message Storage
"""

import os
from flask import Flask
from flask_socketio import SocketIO
from flask_cors import CORS
from dotenv import load_dotenv

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

# Register routes
from routes.page_routes import page_bp
from routes.auth_routes import auth_bp
from routes.user_routes import user_bp
from routes.chat_routes import chat_bp
from routes.socket_routes import register_socket_events

app.register_blueprint(page_bp)
app.register_blueprint(auth_bp, url_prefix='/api')
app.register_blueprint(user_bp, url_prefix='/api')
app.register_blueprint(chat_bp, url_prefix='/api')

# Register WebSocket events
register_socket_events(socketio)

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
