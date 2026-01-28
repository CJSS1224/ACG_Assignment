"""
ST2504 Applied Cryptography - SecureChat Application
=====================================================

Main entry point for the secure messaging application.

Cryptographic Features:
- AES-256-CTR Encryption (Charles)
- HMAC-SHA256 Integrity (Amir)
- RSA Digital Signatures (Yong Cheng)
- RSA-2048 Key Management (Denise)
- bcrypt Password Hashing (Solomon)
- JWT Authentication (Solomon)

Run: python app.py
Open: http://localhost:5000
"""

import os
from flask import Flask, render_template
from flask_socketio import SocketIO
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

from routes.api_routes import api
from routes.socket_routes import register_socket_events

# Initialize Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Register blueprints
app.register_blueprint(api, url_prefix='/api')

# Register WebSocket events
register_socket_events(socketio)


# Page route
@app.route('/')
def index():
    return render_template('index.html')


# Main
if __name__ == '__main__':
    print("=" * 50)
    print("ST2504 Applied Cryptography - SecureChat")
    print("=" * 50)
    print("Cryptographic Features:")
    print("  - AES-256-CTR Encryption (Charles)")
    print("  - HMAC-SHA256 Integrity (Amir)")
    print("  - RSA Digital Signatures (Yong Cheng)")
    print("  - RSA-2048 Key Management (Denise)")
    print("  - bcrypt Password Hashing (Solomon)")
    print("  - JWT Authentication (Solomon)")
    print("=" * 50)
    print("Database: MySQL")
    print("Server: http://localhost:5000")
    print("=" * 50)
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
