# ST2504 Applied Cryptography - SecureChat

A secure end-to-end encrypted messaging application.

## Cryptographic Features

| Feature | Algorithm | Member |
|---------|-----------|--------|
| Message Encryption | AES-256-CTR | Charles |
| Message Integrity | HMAC-SHA256 | Amir |
| Digital Signatures | RSA-PKCS1v15 + SHA256 | Yong Cheng |
| Key Management | RSA-2048 + RSA-OAEP | Denise |
| Key Exchange | **Diffie-Hellman (2048-bit)** | Team |
| Password Hashing | bcrypt (12 rounds) | Solomon |
| Key Derivation | PBKDF2 (100k iterations) | Denise |
| Authentication | JWT HS256 | Solomon |

## Diffie-Hellman Key Exchange (NEW)

When two users are both online:
1. Each user generates a DH keypair on connection
2. DH public keys are exchanged when opening a chat
3. Both users compute the same shared secret: `g^(ab) mod p`
4. Shared secret is used to derive AES key via HKDF
5. Messages show **DH** badge (purple) or **RSA** badge (blue)

**Benefits:**
- **Forward Secrecy** - Past messages stay secure even if RSA keys are compromised
- **Ephemeral Keys** - New DH keys generated each session

## File Structure

```
SecureChat/
├── app.py                  # Main Flask application
├── .env                    # Configuration (DB, JWT secret)
├── requirements.txt        # Python dependencies
│
├── models/                 # Backend Logic
│   ├── crypto_model.py     # ALL cryptographic operations
│   ├── auth_model.py       # Password hashing, JWT tokens
│   └── database_model.py   # MySQL database operations
│
├── routes/                 # API Endpoints
│   ├── api_routes.py       # HTTP REST routes
│   └── socket_routes.py    # WebSocket handlers
│
├── static/js/              # Frontend
│   ├── crypto.js           # Client-side decryption (Web Crypto API)
│   └── app.js              # Application logic
│
├── static/css/
│   └── style.css           # Styling
│
├── templates/
│   └── index.html          # Main page
│
└── database/
    └── schema.sql          # MySQL schema
```

## Setup

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Setup MySQL Database
```bash
mysql -u root -p < database/schema.sql
```

### 3. Configure Environment
Edit `.env` file with your database credentials:
```
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=secure_messaging
JWT_SECRET=your_secret_key
```

### 4. Run Application
```bash
python app.py
```

### 5. Open Browser
```
http://localhost:5000
```

## Message Encryption Flow

### Sending:
1. Generate random AES-256 key
2. Encrypt message with AES-256-CTR
3. Encrypt AES key with recipient's RSA public key (RSA-OAEP)
4. Encrypt AES key with sender's RSA public key (for read-back)
5. Sign ciphertext with sender's RSA private key
6. Generate HMAC-SHA256 for integrity
7. Store encrypted message in database

### Receiving:
1. Decrypt AES key using recipient's RSA private key
2. Decrypt message using AES-256-CTR
3. Verify RSA signature
4. Display message with verification status

## Team Members

- **Solomon** - Server & Authentication (bcrypt, JWT)
- **Charles** - Client Interface & AES Encryption
- **Amir** - HMAC Integrity
- **Yong Cheng** - Digital Signatures
- **Denise** - RSA Key Management
- **Akash** - Database Design
