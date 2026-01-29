# SecureChat

**ST2504 Applied Cryptography - Assignment 2**

A secure messaging application demonstrating cryptographic principles for data protection.

## Security Features

| Requirement | Implementation | Algorithm |
|-------------|----------------|-----------|
| **Integrity in Transit** | HMAC on all WebSocket messages | HMAC-SHA256 |
| **Confidentiality at Rest** | Encrypted message storage | AES-256-GCM |
| **Non-repudiation at Rest** | Digital signatures on messages | RSA-2048-PSS |

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Set Up Database

```bash
mysql -u root -p < database/schema.sql
```

### 3. Configure Environment (Optional)

```bash
export SECRET_KEY="your-secret-key"
export DB_HOST="localhost"
export DB_USER="root"
export DB_PASSWORD="your-password"
export DB_NAME="securechat"
```

### 4. Run the Server

```bash
python app.py
```

### 5. Open Browser

Navigate to `http://localhost:5000`

## Project Structure

```
SecureChat/
├── app.py                  # Main Flask application
├── requirements.txt        # Python dependencies
│
├── crypto/                 # Cryptographic modules
│   ├── __init__.py
│   ├── aes.py              # AES-256-GCM encryption
│   ├── rsa.py              # RSA-OAEP & RSA-PSS
│   ├── kdf.py              # PBKDF2 key derivation
│   └── hmac_utils.py       # HMAC-SHA256 for transit
│
├── models/                 # Business logic
│   ├── __init__.py
│   ├── database.py         # Database operations
│   ├── user.py             # User authentication
│   └── message.py          # Message encryption/decryption
│
├── routes/                 # HTTP & WebSocket routes
│   ├── __init__.py
│   ├── auth.py             # /api/register, /api/login
│   ├── api.py              # /api/chats, /api/messages
│   └── socket.py           # WebSocket event handlers
│
├── database/
│   └── schema.sql          # MySQL schema
│
├── static/
│   ├── js/
│   │   └── app.js          # Client-side application
│   └── css/
│       └── style.css       # Stylesheet
│
└── templates/
    └── index.html          # HTML template
```

## Cryptographic Flow

### User Registration

1. Hash password with **bcrypt** (cost factor 12)
2. Generate **RSA-2048** keypair
3. Derive key from password using **PBKDF2-SHA256** (100,000 iterations)
4. Encrypt private key with **AES-256-GCM**
5. Store: username, password_hash, public_key, encrypted_private_key

### User Login

1. Verify password with **bcrypt**
2. Decrypt private key using **PBKDF2** + **AES-256-GCM**
3. Generate session secret for **HMAC**
4. Return: JWT token, private key, session secret

### Send Message

1. **Verify transit integrity** - Check HMAC on incoming data
2. **Generate AES key** - Random 256-bit key
3. **Encrypt message** - AES-256-GCM (confidentiality)
4. **Encrypt AES key** - RSA-2048-OAEP for recipient
5. **Sign message** - RSA-2048-PSS on ciphertext+nonce (non-repudiation)
6. **Store** - All encrypted data in database

### Receive Message

1. **Decrypt AES key** - RSA-2048-OAEP with private key
2. **Decrypt message** - AES-256-GCM (verifies integrity via tag)
3. **Verify signature** - RSA-2048-PSS (proves sender)
4. **Display** - Show message with verification status

## Database Schema

### Users Table

| Column | Type | Description |
|--------|------|-------------|
| id | INT | Primary key |
| username | VARCHAR(50) | Unique username |
| password_hash | VARCHAR(255) | bcrypt hash |
| public_key | TEXT | RSA public key (PEM) |
| encrypted_private_key | TEXT | AES-GCM encrypted |
| private_key_nonce | VARCHAR(32) | GCM nonce |
| private_key_tag | VARCHAR(32) | GCM auth tag |
| private_key_salt | VARCHAR(32) | PBKDF2 salt |

### Messages Table

| Column | Type | Description |
|--------|------|-------------|
| id | INT | Primary key |
| sender_id | INT | Foreign key to users |
| recipient_id | INT | Foreign key to users |
| ciphertext | TEXT | AES-GCM encrypted message |
| nonce | VARCHAR(32) | GCM nonce |
| tag | VARCHAR(32) | GCM auth tag |
| encrypted_key | TEXT | RSA-encrypted AES key (recipient) |
| encrypted_key_sender | TEXT | RSA-encrypted AES key (sender) |
| signature | TEXT | RSA-PSS signature |

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/register | Create new account |
| POST | /api/login | Authenticate user |
| GET | /api/me | Get current user info |

### Chats & Messages

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/users | List all users |
| GET | /api/chats | Get user's chat list |
| GET | /api/chats/:id/messages | Get messages with user |

### WebSocket Events

| Event | Direction | Description |
|-------|-----------|-------------|
| connect | Client→Server | Establish connection |
| send_message | Client→Server | Send encrypted message |
| new_message | Server→Client | Receive decrypted message |
| user_online | Server→Client | User came online |
| user_offline | Server→Client | User went offline |

## Team Contributions

Add your team member contributions here:

- **Member 1**: [Role/Contribution]
- **Member 2**: [Role/Contribution]
- **Member 3**: [Role/Contribution]
- **Member 4**: [Role/Contribution]
- **Member 5**: [Role/Contribution]
- **Member 6**: [Role/Contribution]

## License

This project is for educational purposes as part of ST2504 Applied Cryptography.
