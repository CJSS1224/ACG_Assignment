"""
SecureChat Application
======================
ST2504 Applied Cryptography Assignment 2

A secure messaging application demonstrating:
    - INTEGRITY IN TRANSIT: HMAC-SHA256 on all messages
    - CONFIDENTIALITY AT REST: AES-256-GCM encryption
    - NON-REPUDIATION AT REST: RSA-PSS digital signatures

Usage:
    python app.py

Configuration:
    Create a .env file with:
    - SECRET_KEY: JWT signing key
    - DB_HOST, DB_USER, DB_PASSWORD, DB_NAME: MySQL connection
"""

import os
import sys

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
from flask import Flask, render_template
from flask_socketio import SocketIO
from flask_cors import CORS

from models import Database
from routes import auth_bp, api_bp, init_auth, init_api, register_socket_events


# =============================================================================
# LOAD ENVIRONMENT VARIABLES
# =============================================================================

# Load .env file from current directory
load_dotenv()


# =============================================================================
# CONFIGURATION
# =============================================================================

class Config:
    """Application configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
    
    # Database configuration
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_USER = os.environ.get('DB_USER', 'root')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', '')
    DB_NAME = os.environ.get('DB_NAME', 'securechat')


# =============================================================================
# APPLICATION FACTORY
# =============================================================================

def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Enable CORS
    CORS(app)
    
    # Initialize Socket.IO
    socketio = SocketIO(app, cors_allowed_origins="*")
    
    # Initialize database
    db = Database(
        host=Config.DB_HOST,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
        database=Config.DB_NAME
    )
    
    # Initialize routes
    init_auth(db)
    init_api(db)
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)
    
    # Register socket events
    register_socket_events(socketio, db, Config.SECRET_KEY)
    
    # ==========================================================================
    # TEMPLATE ROUTES
    # ==========================================================================
    
    @app.route('/')
    def index():
        """Serve the main chat page."""
        return render_template('index.html')
    
    @app.route('/health')
    def health():
        """Health check endpoint."""
        return {'status': 'ok'}
    
    return app, socketio


# =============================================================================
# MAIN
# =============================================================================

if __name__ == '__main__':
    app, socketio = create_app()
    
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                      SECURECHAT SERVER                           ║
╠══════════════════════════════════════════════════════════════════╣
║  ST2504 Applied Cryptography Assignment 2                        ║
║                                                                  ║
║  Security Features:                                              ║
║    ✓ INTEGRITY IN TRANSIT: HMAC-SHA256                          ║
║    ✓ CONFIDENTIALITY AT REST: AES-256-GCM                       ║
║    ✓ NON-REPUDIATION AT REST: RSA-PSS                           ║
║                                                                  ║
║  Server running at: http://localhost:5000                        ║
╚══════════════════════════════════════════════════════════════════╝
    """)
    
    socketio.run(app, 
             debug=True, 
             host='0.0.0.0', 
             port=5000,
            ssl_context=('SSL-Certs/localhost-cert.pem', 'SSL-Certs/localhost-key.pem')
            )