"""
Constants Module

This module defines all configuration constants used throughout the
secure messaging application. Centralizing these values ensures
consistency and makes configuration changes easy.

Author: Shared (All Team Members)
"""

import os

# =============================================================================
# NETWORK CONFIGURATION
# =============================================================================

# Server host address
# LEARN: '127.0.0.1' is localhost - the server runs on your own machine
# LEARN: For testing across different computers, change this to the server's
# LEARN: actual IP address (e.g., '192.168.1.100')
SERVER_HOST = '127.0.0.1'

# Server port number
# LEARN: Ports below 1024 require admin privileges, so we use a high port
# LEARN: Make sure this port isn't already in use by another application
SERVER_PORT = 5000

# Socket buffer size in bytes
# LEARN: This is how much data we read from the network at once
# LEARN: 4096 bytes (4KB) is a common choice - large enough for messages
# LEARN: but not so large that it wastes memory
BUFFER_SIZE = 4096

# Connection timeout in seconds
# LEARN: If no data is received within this time, the connection is dropped
# LEARN: Prevents hanging connections from blocking the server
CONNECTION_TIMEOUT = 300  # 5 minutes

# Maximum number of pending connections
# LEARN: This is the 'backlog' parameter for socket.listen()
# LEARN: It's how many clients can wait in queue before being rejected
MAX_PENDING_CONNECTIONS = 5


# =============================================================================
# CRYPTOGRAPHIC PARAMETERS
# =============================================================================

# AES key size in bytes (256 bits = 32 bytes)
# LEARN: AES supports 128, 192, or 256 bit keys
# LEARN: 256-bit is the strongest and recommended for sensitive data
# LEARN: 32 bytes * 8 bits/byte = 256 bits
AES_KEY_SIZE = 32

# AES block size in bytes (always 128 bits for AES)
# LEARN: AES always uses 128-bit (16 byte) blocks regardless of key size
# LEARN: This is important for padding calculations in CBC mode
AES_BLOCK_SIZE = 16

# RSA key size in bits
# LEARN: 2048 bits is the current minimum recommended for RSA
# LEARN: 4096 bits is more secure but slower - 2048 is fine for this assignment
RSA_KEY_SIZE = 2048

# HMAC key size in bytes
# LEARN: For HMAC-SHA256, the key should be at least 32 bytes
# LEARN: to match the hash output size for optimal security
HMAC_KEY_SIZE = 32


# =============================================================================
# CERTIFICATE PARAMETERS
# =============================================================================

# Certificate validity period in days
# LEARN: Certificates expire after this many days and must be renewed
# LEARN: 365 days (1 year) is common for demo/development certificates
CERT_VALIDITY_DAYS = 365

# Certificate Authority (CA) information
# LEARN: These values appear in the CA certificate's subject field
# LEARN: In a real system, this would be a trusted organization
CA_COUNTRY = "SG"
CA_STATE = "Singapore"
CA_LOCALITY = "Singapore"
CA_ORGANIZATION = "ST2504 Applied Cryptography"
CA_COMMON_NAME = "ST2504 Assignment CA"

# Server certificate information
SERVER_COMMON_NAME = "SecureMessaging Server"


# =============================================================================
# FILE PATHS
# =============================================================================

# LEARN: os.path.dirname gets the directory containing a file
# LEARN: os.path.abspath gets the full absolute path
# LEARN: We go up 3 levels from this file to get the project root:
# LEARN: constants.py -> utils/ -> src/ -> ST2504_ACG_Assignment2/

# Get the project root directory
# LEARN: __file__ is the path to this constants.py file
# LEARN: Path: constants.py -> utils/ -> src/ -> ST2504_ACG_Assignment2/
# LEARN: So we need to go up 3 levels
PROJECT_ROOT = os.path.dirname(  # -> ST2504_ACG_Assignment2/
    os.path.dirname(              # -> src/
        os.path.dirname(          # -> utils/
            os.path.abspath(__file__)  # constants.py
        )
    )
)

# Certificate directories
CERTS_DIR = os.path.join(PROJECT_ROOT, 'certs')
CA_CERTS_DIR = os.path.join(CERTS_DIR, 'ca')
SERVER_CERTS_DIR = os.path.join(CERTS_DIR, 'server')

# Key directories
KEYS_DIR = os.path.join(PROJECT_ROOT, 'keys')
CLIENT_KEYS_DIR = os.path.join(KEYS_DIR, 'clients')

# Data directories
DATA_DIR = os.path.join(PROJECT_ROOT, 'data')
MESSAGES_DIR = os.path.join(DATA_DIR, 'messages')
LOGS_DIR = os.path.join(DATA_DIR, 'logs')

# Certificate file paths
CA_CERTIFICATE_PATH = os.path.join(CA_CERTS_DIR, 'ca_certificate.pem')
CA_PRIVATE_KEY_PATH = os.path.join(CA_CERTS_DIR, 'ca_private_key.pem')
SERVER_CERTIFICATE_PATH = os.path.join(SERVER_CERTS_DIR, 'server_certificate.pem')
SERVER_PRIVATE_KEY_PATH = os.path.join(SERVER_CERTS_DIR, 'server_private_key.pem')


# =============================================================================
# SECURITY PARAMETERS
# =============================================================================

# Maximum message age for replay attack prevention (in seconds)
# LEARN: If a message timestamp is older than this, we reject it
# LEARN: This prevents attackers from capturing and re-sending old messages
MAX_MESSAGE_AGE = 300  # 5 minutes

# Nonce size in bytes
# LEARN: A nonce (number used once) prevents replay attacks
# LEARN: 16 bytes = 128 bits provides plenty of randomness
NONCE_SIZE = 16

# Password for private key encryption (for demo purposes)
# LEARN: In production, this should be user-provided or from a secure vault
# LEARN: NEVER hardcode passwords in real applications!
DEFAULT_KEY_PASSWORD = b"st2504_assignment_password"


# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

# Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_LEVEL = "INFO"

# Log format string
# LEARN: This defines how each log message looks
# LEARN: %(asctime)s = timestamp, %(levelname)s = DEBUG/INFO/etc
# LEARN: %(name)s = logger name, %(message)s = actual message
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(name)s - %(message)s"

# Log file names
SERVER_LOG_FILE = os.path.join(LOGS_DIR, 'server.log')
CLIENT_LOG_FILE = os.path.join(LOGS_DIR, 'client.log')


# =============================================================================
# MESSAGE PROTOCOL CONSTANTS
# =============================================================================

# Protocol version (for future compatibility)
PROTOCOL_VERSION = "1.0"

# Message field separators
# LEARN: We use these special strings to separate parts of a message
# LEARN: They're chosen to be unlikely to appear in actual message content
FIELD_SEPARATOR = "||"
MESSAGE_END = "<<END>>"

# Maximum message size in bytes
# LEARN: Prevents denial-of-service attacks using huge messages
MAX_MESSAGE_SIZE = 1024 * 1024  # 1 MB


# =============================================================================
# ENCODING
# =============================================================================

# Default text encoding
# LEARN: UTF-8 is the standard encoding that supports all characters
TEXT_ENCODING = 'utf-8'

# Base64 encoding for binary data
# LEARN: When we need to send binary data (like encrypted bytes) as text,
# LEARN: we encode it as Base64 which uses only printable ASCII characters
