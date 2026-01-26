================================================================================
ST2504 Applied Cryptography - SecureChat Application
================================================================================

OVERVIEW
--------
SecureChat is a secure messaging application that demonstrates cryptographic
concepts for protecting message confidentiality, integrity, and non-repudiation.

All cryptographic operations are implemented in Python using the 'cryptography'
library.


SECURITY FEATURES
-----------------
1. Confidentiality (At-Rest): AES-256-CTR encryption (Member 3)
2. Integrity: HMAC-SHA256 (Member 4)
3. Non-Repudiation: RSA Digital Signatures (Member 5)
4. Key Management: RSA-2048 keypairs, RSA-OAEP key exchange (Member 6)
5. Authentication: bcrypt password hashing, JWT tokens (Member 1)


REQUIREMENTS
------------
- Python 3.8+
- MySQL 8.0+
- pip (Python package manager)


INSTALLATION
------------
1. Install Python dependencies:
   pip install -r requirements.txt

2. Set up MySQL database:
   mysql -u root -p < database/schema.sql

3. Configure environment:
   - Copy .env.example to .env
   - Update database credentials in .env

4. Run the application:
   python app.py

5. Open browser:
   http://localhost:5000


FILE STRUCTURE
--------------
SecureChat/
├── app.py                      # Main Flask application (Member 1)
├── services/
│   ├── auth_service.py         # Authentication & JWT (Member 1)
│   ├── crypto_service.py       # All cryptographic operations (Member 3,4,5,6)
│   └── database_service.py     # Database operations (Member 1)
├── templates/
│   └── index.html              # Chat interface (Member 2)
├── static/
│   ├── css/style.css           # Styling (Member 2)
│   └── js/app.js               # UI interactions (Member 2)
├── database/
│   └── schema.sql              # MySQL schema
├── requirements.txt            # Python dependencies
├── .env                        # Configuration
└── readme.txt                  # This file


CRYPTOGRAPHIC IMPLEMENTATION
----------------------------

Message Encryption Flow:
1. Generate random AES-256 key
2. Encrypt message with AES-256-CTR
3. Encrypt AES key with recipient's RSA public key (RSA-OAEP)
4. Encrypt AES key with sender's RSA public key (for reading own messages)
5. Sign ciphertext with sender's RSA private key (RSASSA-PKCS1-v1_5)
6. Generate HMAC-SHA256 for integrity

Message Decryption Flow:
1. Decrypt AES key using recipient's RSA private key
2. Decrypt message using AES-256-CTR
3. Verify signature using sender's RSA public key


TEAM MEMBERS
------------
- Solomon: Server & Authentication (app.py, auth_service.py, database_service.py)
- Charles: Client Interface (index.html, style.css, app.js)
- Charles: AES Encryption (crypto_service.py - AES section)
- Amir: HMAC Integrity (crypto_service.py - HMAC section)
- Yong Cheng: Digital Signatures (crypto_service.py - Signature section)
- Denise: Key Management (crypto_service.py - RSA section)
- Akash: Database & Message Storage


USAGE
-----
1. Register a new account (RSA keypair generated automatically)
2. Login with credentials
3. Click "New Chat" to see online users
4. Select a user to start chatting
5. Messages are encrypted before storage and decrypted on retrieval


NOTES
-----
- Private keys are stored in browser localStorage (for demo purposes)
- In production, use more secure key storage methods
- Use HTTPS in production for secure transit
