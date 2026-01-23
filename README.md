# ST2504 Applied Cryptography - SecureChat Web Application

A secure end-to-end encrypted messaging web application built with Flask, WebSocket, and MySQL.

## Features

- **User Authentication**: Register, login, and logout with secure password hashing (bcrypt)
- **End-to-End Encryption**: Messages encrypted with AES-256-CBC
- **Digital Signatures**: RSA-2048 signatures for non-repudiation
- **Message Integrity**: HMAC-SHA256 verification
- **Real-time Messaging**: WebSocket for instant message delivery
- **Modern UI**: WhatsApp/Telegram-style chat interface

## Security Properties

| Property | Implementation |
|----------|---------------|
| **Confidentiality** | AES-256-CBC encryption with unique key per message |
| **Integrity** | HMAC-SHA256 on all messages |
| **Non-repudiation** | RSA-2048 digital signatures |
| **Authentication** | JWT tokens + bcrypt password hashing |
| **Key Exchange** | RSA-OAEP encrypted session keys |

## Requirements

- Python 3.10+
- MySQL 8.0+
- Modern web browser with Web Crypto API support

## Installation

### 1. Clone/Extract the project

```bash
cd ST2504_ACG_WebApp
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Set up MySQL database

```bash
# Login to MySQL
mysql -u root -p

# Run the schema script
source database/schema.sql
```

### 4. Configure environment variables

```bash
# Copy example env file
cp .env.example .env

# Edit .env with your settings
nano .env
```

Required settings in `.env`:
```
FLASK_SECRET_KEY=your-random-secret-key
JWT_SECRET=your-jwt-secret-key
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your-mysql-password
DB_DATABASE=secure_messaging
```

### 5. Run the application

```bash
python app.py
```

The server will start at `http://127.0.0.1:5000`

## Usage

### 1. Register a new account
- Open `http://127.0.0.1:5000` in your browser
- Click "Register" and create an account
- Your RSA key pair is generated automatically

### 2. Login
- Use your username and password to login
- Your private key is stored securely in the browser

### 3. Start a chat
- Click the "+" button in the sidebar
- Select an online user from the list
- Start sending encrypted messages!

### 4. Chat features
- Messages are encrypted end-to-end
- Digital signatures verify sender identity
- Typing indicators show when others are typing
- Online/offline status displayed

## Project Structure

```
ST2504_ACG_WebApp/
├── app.py                      # Main Flask application
├── requirements.txt            # Python dependencies
├── .env.example               # Environment variables template
│
├── database/
│   └── schema.sql             # MySQL database schema
│
├── src/
│   ├── database.py            # Database connection pool
│   ├── models/
│   │   ├── user_model.py      # User database operations
│   │   └── message_model.py   # Message database operations
│   ├── services/
│   │   ├── auth_service.py    # Authentication (JWT, bcrypt)
│   │   └── crypto_service.py  # Server-side crypto wrapper
│   ├── crypto/                # Existing crypto modules
│   │   ├── encryption.py      # AES-256 encryption
│   │   ├── integrity.py       # HMAC-SHA256
│   │   └── signatures.py      # RSA signatures
│   ├── pki/
│   │   └── key_management.py  # RSA key generation
│   └── utils/
│       ├── constants.py       # Configuration
│       ├── helpers.py         # Utility functions
│       └── protocol.py        # Message protocol
│
├── static/
│   ├── css/
│   │   └── style.css          # Chat UI styling
│   └── js/
│       ├── crypto.js          # Browser crypto (Web Crypto API)
│       └── app.js             # Main application logic
│
└── templates/
    └── index.html             # Main HTML page
```

## API Endpoints

### Authentication
- `POST /api/register` - Register new user
- `POST /api/login` - Login user
- `POST /api/logout` - Logout user
- `GET /api/me` - Get current user info

### Users
- `GET /api/users/online` - Get online users
- `GET /api/users/<id>/public-key` - Get user's public key

### Chats
- `GET /api/chats` - Get user's chats
- `POST /api/chats` - Create new chat
- `GET /api/chats/<user_id>/messages` - Get chat messages

### WebSocket Events
- `connect` - Connect with JWT token
- `send_message` - Send encrypted message
- `new_message` - Receive new message
- `user_online` - User came online
- `user_offline` - User went offline
- `typing` - Typing indicator

## Cryptographic Flow

### Message Sending
1. Generate random AES-256 key for this message
2. Encrypt message with AES-256-CBC
3. Encrypt AES key with recipient's RSA public key
4. Sign payload with sender's RSA private key
5. Generate HMAC for integrity
6. Send via WebSocket

### Message Receiving
1. Decrypt AES key with recipient's private key
2. Decrypt message with AES key
3. Verify signature with sender's public key
4. Verify HMAC integrity

## Testing

1. Open two browser windows/tabs
2. Register two different users (e.g., Alice and Bob)
3. Login as both users
4. Start a chat between them
5. Send messages and verify encryption/decryption works

## Troubleshooting

### Database connection error
- Verify MySQL is running
- Check `.env` database credentials
- Ensure `secure_messaging` database exists

### WebSocket connection failed
- Check if server is running
- Verify JWT token is valid
- Check browser console for errors

### Encryption/decryption errors
- Clear browser localStorage and re-register
- Ensure both users have valid public keys

## Team Members

1. Member 1: [Name] - Server Development
2. Member 2: [Name] - Client Development  
3. Member 3: [Name] - AES Encryption Module
4. Member 4: [Name] - HMAC Integrity Module
5. Member 5: [Name] - Digital Signatures Module
6. Member 6: [Name] - Key Management/PKI Module

## License

ST2504 Applied Cryptography Assignment - Singapore Polytechnic
