# ACG Assignment 2 - Project File Structure

## Complete Directory Structure

```
ST2504_ACG_Assignment2/
│
├── README.txt
├── requirements.txt
├── .gitignore
│
├── src/
│   ├── __init__.py
│   │
│   ├── server/
│   │   ├── __init__.py
│   │   └── server.py                 # Member 1 - Main server application
│   │
│   ├── client/
│   │   ├── __init__.py
│   │   └── client.py                 # Member 2 - Main client application
│   │
│   ├── crypto/
│   │   ├── __init__.py
│   │   ├── encryption.py             # Member 3 - AES encryption/decryption
│   │   ├── integrity.py              # Member 4 - HMAC and hash functions
│   │   └── signatures.py             # Member 5 - Digital signatures (RSA)
│   │
│   ├── pki/
│   │   ├── __init__.py
│   │   └── key_management.py         # Member 6 - PKI and key management
│   │
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── constants.py              # Shared constants (ports, paths, etc.)
│   │   ├── helpers.py                # Common utility functions
│   │   └── protocol.py               # Message protocol definitions
│   │
│   └── tests/
│       ├── __init__.py
│       ├── test_encryption.py        # Member 3 - Test encryption functions
│       ├── test_integrity.py         # Member 4 - Test integrity functions
│       ├── test_signatures.py        # Member 5 - Test signature functions
│       └── test_key_management.py    # Member 6 - Test PKI functions
│
├── certs/
│   ├── .gitkeep
│   ├── ca/
│   │   ├── ca_certificate.pem        # Certificate Authority certificate
│   │   └── ca_private_key.pem        # CA private key (keep secure!)
│   │
│   └── server/
│       ├── server_certificate.pem    # Server's certificate
│       └── server_private_key.pem    # Server's private key
│
├── keys/
│   ├── .gitkeep
│   └── clients/                      # Client keys generated at runtime
│       └── .gitkeep
│
├── data/
│   ├── .gitkeep
│   ├── messages/                     # Encrypted messages stored at rest
│   │   └── .gitkeep
│   └── logs/                         # Server/client logs
│       └── .gitkeep
│
├── docs/
│   └── proposal_report.docx          # Final proposal report
│
└── scripts/
    ├── setup_ca.py                   # Script to initialize CA certificates
    └── generate_test_keys.py         # Script to generate test keys
```

---

## File Descriptions and Ownership

### Root Files

| File | Description | Owner |
|------|-------------|-------|
| `README.txt` | How to run the program (required by assignment) | Member 1 or 2 |
| `requirements.txt` | Python dependencies | Anyone |
| `.gitignore` | Git ignore rules | Anyone |

---

### src/server/ (Member 1)

**server.py**
```python
# Member 1: [Name]
# Description: Main server application
# - Socket server setup and connection handling
# - Client authentication
# - Message routing between clients
# - Message storage (encrypted at rest)
```

---

### src/client/ (Member 2)

**client.py**
```python
# Member 2: [Name]
# Description: Main client application
# - Socket client connection
# - User interface (command-line)
# - Send and receive messages
# - Key registration with server
```

---

### src/crypto/ (Members 3, 4, 5)

**encryption.py (Member 3)**
```python
# Member 3: [Name]
# Description: AES encryption and decryption functions
# Functions:
#   - generate_aes_key()
#   - encrypt_message(plaintext, key)
#   - decrypt_message(ciphertext, key)
#   - encrypt_file(filepath, key)  # Optional
#   - decrypt_file(filepath, key)  # Optional
```

**integrity.py (Member 4)**
```python
# Member 4: [Name]
# Description: HMAC and integrity verification
# Functions:
#   - generate_hmac(message, key)
#   - verify_hmac(message, hmac_value, key)
#   - hash_message(message)  # SHA-256
#   - generate_nonce()
#   - verify_timestamp(timestamp, max_age)
```

**signatures.py (Member 5)**
```python
# Member 5: [Name]
# Description: RSA digital signatures for non-repudiation
# Functions:
#   - sign_message(message, private_key)
#   - verify_signature(message, signature, public_key)
#   - load_private_key(filepath)
#   - load_public_key(filepath)
```

---

### src/pki/ (Member 6)

**key_management.py (Member 6)**
```python
# Member 6: [Name]
# Description: PKI and key management
# Functions:
#   - generate_rsa_keypair()
#   - save_private_key(key, filepath, password)
#   - save_public_key(key, filepath)
#   - load_private_key(filepath, password)
#   - load_public_key(filepath)
#   - generate_certificate(subject, issuer_key, issuer_cert)
#   - verify_certificate(cert, ca_cert)
#   - generate_session_key()
#   - encrypt_key_with_rsa(symmetric_key, public_key)
#   - decrypt_key_with_rsa(encrypted_key, private_key)
```

---

### src/utils/ (Shared)

**constants.py**
```python
# Shared constants used across the project
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5000
BUFFER_SIZE = 4096
AES_KEY_SIZE = 32  # 256 bits
RSA_KEY_SIZE = 2048
CERT_VALIDITY_DAYS = 365
```

**helpers.py**
```python
# Common utility functions
# - format_message()
# - parse_message()
# - timestamp_now()
# - bytes_to_base64()
# - base64_to_bytes()
```

**protocol.py**
```python
# Message protocol definitions
# - Message types (REGISTER, MESSAGE, RETRIEVE, etc.)
# - Message format structure
# - Serialization/deserialization
```

---

### scripts/ (Setup Scripts)

**setup_ca.py**
```python
# Run once to set up Certificate Authority
# Creates ca_certificate.pem and ca_private_key.pem
# Creates server certificate signed by CA
```

**generate_test_keys.py**
```python
# Generate test client keys for development
# Useful for testing without full registration flow
```

---

## File Contents Templates

### README.txt
```
ST2504 Applied Cryptography - Assignment 2
Secure Messaging Application

TEAM MEMBERS:
1. [Name] - Server Development
2. [Name] - Client Development
3. [Name] - Encryption Module
4. [Name] - Integrity Module
5. [Name] - Digital Signatures Module
6. [Name] - Key Management Module

REQUIREMENTS:
- Python 3.10 or higher
- cryptography library

INSTALLATION:
1. pip install -r requirements.txt
2. python scripts/setup_ca.py (first time only)

RUNNING THE APPLICATION:
1. Start the server:
   python -m src.server.server

2. Start client(s) in separate terminals:
   python -m src.client.client

USAGE:
1. Register with a username when prompted
2. Send messages to other connected users
3. Messages are encrypted and signed automatically

FILE STRUCTURE:
- src/server/     : Server application
- src/client/     : Client application
- src/crypto/     : Cryptographic functions
- src/pki/        : Key management
- certs/          : Certificates
- keys/           : Generated keys
- data/           : Stored messages
```

### requirements.txt
```
cryptography>=41.0.0
```

### .gitignore
```
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
venv/
ENV/
.venv/

# IDE
.vscode/
.idea/
*.swp
*.swo

# Project specific - DO NOT commit private keys in production
# For assignment purposes, we include them
# certs/ca/ca_private_key.pem
# certs/server/server_private_key.pem
# keys/clients/*

# Logs
*.log
data/logs/*
!data/logs/.gitkeep

# OS
.DS_Store
Thumbs.db
```

---

## Module Dependencies Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        constants.py                          │
│                         helpers.py                           │
│                         protocol.py                          │
└─────────────────────────────────────────────────────────────┘
                              ▲
                              │ imports
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────────┐
│ encryption.py │    │ integrity.py │    │ key_management.py │
│  (Member 3)   │    │  (Member 4)  │    │    (Member 6)     │
└──────────────┘    └──────────────┘    └──────────────────┘
        │                     │                     │
        │                     ▼                     │
        │            ┌──────────────┐               │
        └───────────►│ signatures.py │◄──────────────┘
                     │  (Member 5)   │
                     └──────────────┘
                              ▲
                              │ imports all crypto modules
                ┌─────────────┴─────────────┐
                │                           │
                ▼                           ▼
        ┌──────────────┐           ┌──────────────┐
        │  server.py   │◄─────────►│  client.py   │
        │  (Member 1)  │  network  │  (Member 2)  │
        └──────────────┘           └──────────────┘
```

---

## GitHub Branch Strategy

```
main (protected)
│
├── dev (integration branch)
│   │
│   ├── feature/server          (Member 1)
│   ├── feature/client          (Member 2)
│   ├── feature/encryption      (Member 3)
│   ├── feature/integrity       (Member 4)
│   ├── feature/signatures      (Member 5)
│   └── feature/key-management  (Member 6)
```

### Workflow:
1. Each member works on their feature branch
2. When ready, create Pull Request to `dev`
3. Another member reviews and approves
4. Merge to `dev`
5. Test integration on `dev`
6. When stable, merge `dev` to `main`

---

## Development Timeline Suggestion

| Week | Task | Members |
|------|------|---------|
| Week 1 | Set up repo, agree on interfaces, create skeleton files | All |
| Week 1-2 | Develop individual modules | 3, 4, 5, 6 |
| Week 2 | Develop server and client skeletons | 1, 2 |
| Week 2-3 | Integration - connect modules | All |
| Week 3 | Testing and bug fixes | All |
| Week 3 | Write report sections | All |
| Week 4 | Final testing, demo preparation | All |

---

## Quick Start Commands

```bash
# Clone repository
git clone https://github.com/your-team/ST2504_ACG_Assignment2.git
cd ST2504_ACG_Assignment2

# Set up virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Initialize CA and certificates (first time)
python scripts/setup_ca.py

# Run server
python -m src.server.server

# Run client (new terminal)
python -m src.client.client
```