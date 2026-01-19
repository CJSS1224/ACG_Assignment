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
SERVER_HOST = '127.0.0.1'

# Server port number
SERVER_PORT = 5000

# Socket buffer size in bytes
BUFFER_SIZE = 4096

# Connection timeout in seconds
CONNECTION_TIMEOUT = 300  # 5 minutes

# Maximum number of pending connections
MAX_PENDING_CONNECTIONS = 5


# =============================================================================
# CRYPTOGRAPHIC PARAMETERS
# =============================================================================

# AES key size in bytes (256 bits = 32 bytes)
AES_KEY_SIZE = 32

# AES block size in bytes (always 128 bits for AES)
AES_BLOCK_SIZE = 16

# RSA key size in bits
RSA_KEY_SIZE = 2048

# HMAC key size in bytes
HMAC_KEY_SIZE = 32


# =============================================================================
# CERTIFICATE PARAMETERS
# =============================================================================

# Certificate validity period in days
CERT_VALIDITY_DAYS = 365

# Certificate Authority (CA) information
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


# Get the project root directory
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
MAX_MESSAGE_AGE = 300  # 5 minutes

# Nonce size in bytes
NONCE_SIZE = 16

# Password for private key encryption (for demo purposes)
DEFAULT_KEY_PASSWORD = b"st2504_assignment_password"


# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

# Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_LEVEL = "INFO"

# Log format string
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
FIELD_SEPARATOR = "||"
MESSAGE_END = "<<END>>"

# Maximum message size in bytes
MAX_MESSAGE_SIZE = 1024 * 1024  # 1 MB


# =============================================================================
# ENCODING
# =============================================================================

# Default text encoding
TEXT_ENCODING = 'utf-8'

# Base64 encoding for binary data
