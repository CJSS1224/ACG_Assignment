================================================================================
ST2504 Applied Cryptography - Assignment 2
Secure Messaging Application
================================================================================

TEAM MEMBERS:
-------------
1. Member 1: [Name] - Server Development (server.py)
2. Member 2: [Name] - Client Development (client.py)
3. Member 3: [Name] - AES Encryption Module (encryption.py)
4. Member 4: [Name] - Integrity/HMAC Module (integrity.py)
5. Member 5: [Name] - Digital Signatures Module (signatures.py)
6. Member 6: [Name] - Key Management/PKI Module (key_management.py)

================================================================================
DESCRIPTION
================================================================================

This is a secure messaging application that demonstrates the implementation
of cryptographic security principles:

SECURITY PROPERTIES:
- CONFIDENTIALITY: AES-256-CBC encryption ensures only authorized parties
                   can read message content
- INTEGRITY:       HMAC-SHA256 detects any tampering during transmission
- NON-REPUDIATION: RSA digital signatures prove message origin

ARCHITECTURE:
- Client-Server model using TCP sockets
- Server acts as message router and certificate authority
- Each client has unique RSA key pair and certificate
- Session keys exchanged securely using RSA encryption

================================================================================
REQUIREMENTS
================================================================================

- Python 3.10 or higher
- cryptography library (version 41.0.0 or higher)

================================================================================
INSTALLATION
================================================================================

1. Install Python dependencies:

   pip install -r requirements.txt

   OR if you encounter permission issues:

   pip install -r requirements.txt --user

2. Initialize the Certificate Authority (first time only):

   python scripts/setup_ca.py

   This creates:
   - CA certificate and private key
   - Server certificate and private key

================================================================================
RUNNING THE APPLICATION
================================================================================

STEP 1: Start the Server
------------------------
Open a terminal/command prompt and run:

   python -m src.server.server

You should see:
   [SERVER] Listening on 127.0.0.1:5000
   [SERVER] Press Ctrl+C to stop


STEP 2: Start Client(s)
-----------------------
Open another terminal/command prompt and run:

   python -m src.client.client

You will be prompted to:
1. Enter a username (minimum 3 characters)
2. Wait for key exchange to complete

You can start multiple clients in separate terminals to test messaging
between users.


STEP 3: Send Messages
---------------------
Once connected, use these commands:

   /msg <username> <message>  - Send encrypted message to a user
   /users                     - List online users
   /help                      - Show available commands
   /quit                      - Disconnect and exit

Example:
   /msg Alice Hello, how are you?
   /users

================================================================================
PROJECT STRUCTURE
================================================================================

ST2504_ACG_Assignment2/
├── README.txt              <- You are here
├── requirements.txt        <- Python dependencies
├── .gitignore              <- Git ignore rules
│
├── src/                    <- Source code
│   ├── server/
│   │   └── server.py       <- Server application (Member 1)
│   │
│   ├── client/
│   │   └── client.py       <- Client application (Member 2)
│   │
│   ├── crypto/
│   │   ├── encryption.py   <- AES encryption (Member 3)
│   │   ├── integrity.py    <- HMAC functions (Member 4)
│   │   └── signatures.py   <- Digital signatures (Member 5)
│   │
│   ├── pki/
│   │   └── key_management.py <- PKI operations (Member 6)
│   │
│   ├── utils/
│   │   ├── constants.py    <- Configuration values
│   │   ├── helpers.py      <- Utility functions
│   │   └── protocol.py     <- Message protocol
│   │
│   └── tests/              <- Unit tests
│       ├── test_encryption.py
│       ├── test_integrity.py
│       ├── test_signatures.py
│       └── test_key_management.py
│
├── certs/                  <- Certificates
│   ├── ca/                 <- Certificate Authority
│   │   ├── ca_certificate.pem
│   │   └── ca_private_key.pem
│   └── server/             <- Server certificates
│       ├── server_certificate.pem
│       └── server_private_key.pem
│
├── keys/                   <- Generated keys
│   └── clients/            <- Client keys (generated at runtime)
│
├── data/                   <- Runtime data
│   ├── messages/           <- Encrypted stored messages
│   └── logs/               <- Log files
│
└── scripts/
    └── setup_ca.py         <- CA initialization script

================================================================================
RUNNING TESTS
================================================================================

To run all unit tests:

   python -m pytest src/tests/ -v

To run specific test file:

   python -m pytest src/tests/test_encryption.py -v

================================================================================
CRYPTOGRAPHIC ALGORITHMS USED
================================================================================

1. SYMMETRIC ENCRYPTION
   - Algorithm: AES-256-CBC
   - Key Size: 256 bits (32 bytes)
   - Mode: Cipher Block Chaining
   - Padding: PKCS7
   - Purpose: Message confidentiality

2. MESSAGE AUTHENTICATION
   - Algorithm: HMAC-SHA256
   - Key Size: 256 bits (32 bytes)
   - Purpose: Message integrity verification

3. DIGITAL SIGNATURES
   - Algorithm: RSA with PKCS#1 v1.5 padding
   - Key Size: 2048 bits
   - Hash: SHA-256
   - Purpose: Non-repudiation

4. KEY EXCHANGE
   - Algorithm: RSA-OAEP
   - Key Size: 2048 bits
   - Purpose: Secure session key exchange

5. CERTIFICATES
   - Standard: X.509 v3
   - Validity: 365 days
   - Purpose: Identity verification

================================================================================
SECURITY FEATURES
================================================================================

1. CONFIDENTIALITY (At-Rest and In-Transit)
   - Messages encrypted with AES-256 before transmission
   - Stored messages encrypted on server disk
   - Session keys exchanged using RSA encryption

2. INTEGRITY VERIFICATION
   - Every message includes HMAC
   - Server and client verify HMAC before processing
   - Tampering is detected and message rejected

3. NON-REPUDIATION
   - Messages signed with sender's RSA private key
   - Signature stored with message for audit trail
   - Sender cannot deny having sent the message

4. REPLAY ATTACK PREVENTION
   - Messages include timestamp and nonce
   - Server rejects messages with:
     - Timestamps older than 5 minutes
     - Previously-used nonces

5. MAN-IN-THE-MIDDLE PREVENTION
   - Certificate-based authentication
   - Public keys verified against CA certificate
   - Session keys encrypted with recipient's public key

================================================================================
TROUBLESHOOTING
================================================================================

Problem: "Module not found" error
Solution: Make sure you're running from the project root directory

Problem: "Connection refused" error
Solution: Make sure the server is running before starting clients

Problem: "Address already in use" error
Solution: Wait a few seconds and try again, or change the port in constants.py

Problem: "Certificate not found" error
Solution: Run "python scripts/setup_ca.py" to initialize certificates

================================================================================
NOTES
================================================================================

- This is an educational implementation for demonstrating cryptographic concepts
- In production, use established protocols like TLS/SSL
- Private keys in this demo use a default password for simplicity
- In production, use strong, unique passwords for key protection

================================================================================
