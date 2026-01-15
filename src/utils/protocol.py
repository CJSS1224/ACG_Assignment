"""
Protocol Module

This module defines the message protocol used for communication between
the client and server. It includes:
- Message types (enumerations)
- Message structure and format
- Serialization and deserialization functions

The protocol ensures consistent message formatting and enables proper
parsing of encrypted, signed messages.

Author: Shared (All Team Members)
"""

import json
from enum import Enum, auto
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any

from src.utils.constants import PROTOCOL_VERSION, TEXT_ENCODING
from src.utils.helpers import get_timestamp, bytes_to_base64, base64_to_bytes


# =============================================================================
# MESSAGE TYPES
# =============================================================================

class MessageType(Enum):
    """
    Enumeration of all message types in the protocol.
    
    Each message sent between client and server has a type that determines
    how it should be processed.
    """
    # LEARN: Enum (enumeration) is a way to define a set of named constants
    # LEARN: Instead of using magic strings like "REGISTER" throughout the code,
    # LEARN: we use MessageType.REGISTER which is type-checked and auto-completed
    # LEARN: auto() automatically assigns incrementing integer values
    
    # Client registration and authentication
    REGISTER = auto()           # Client wants to register with username
    REGISTER_ACK = auto()       # Server acknowledges registration
    REGISTER_FAIL = auto()      # Registration failed
    
    # Key exchange
    KEY_EXCHANGE = auto()       # Client sends public key to server
    KEY_EXCHANGE_ACK = auto()   # Server acknowledges key receipt
    SESSION_KEY = auto()        # Server sends encrypted session key
    GET_PUBLIC_KEY = auto()     # Client requests another user's public key
    PUBLIC_KEY_RESPONSE = auto() # Server sends requested public key
    
    # Messaging
    SEND_MESSAGE = auto()       # Client sends a message to another user
    RECEIVE_MESSAGE = auto()    # Server delivers a message to client
    MESSAGE_ACK = auto()        # Acknowledge message receipt
    
    # Message retrieval
    FETCH_MESSAGES = auto()     # Client requests stored messages
    MESSAGE_LIST = auto()       # Server sends list of stored messages
    
    # User management
    LIST_USERS = auto()         # Client requests list of online users
    USER_LIST = auto()          # Server sends list of online users
    USER_JOINED = auto()        # Notification: user came online
    USER_LEFT = auto()          # Notification: user went offline
    
    # Connection management
    DISCONNECT = auto()         # Client is disconnecting
    PING = auto()               # Keep-alive ping
    PONG = auto()               # Keep-alive response
    
    # Errors
    ERROR = auto()              # General error message


# =============================================================================
# MESSAGE DATA CLASS
# =============================================================================

@dataclass
class Message:
    """
    Represents a message in the secure messaging protocol.
    
    This class encapsulates all the data needed for a complete message,
    including the encrypted payload, integrity hash, and digital signature.
    
    Attributes:
        msg_type: Type of message (from MessageType enum)
        sender: Username of the sender
        recipient: Username of the recipient (None for broadcast/server messages)
        payload: The actual message content (encrypted for sensitive data)
        timestamp: Unix timestamp when message was created
        nonce: Random value to prevent replay attacks
        hmac: HMAC for integrity verification during transit
        signature: Digital signature for non-repudiation
        version: Protocol version for compatibility
    """
    # LEARN: @dataclass is a Python decorator that automatically generates
    # LEARN: __init__, __repr__, __eq__ and other methods for a class
    # LEARN: It's perfect for data container classes like messages
    
    msg_type: MessageType
    sender: str
    recipient: Optional[str] = None
    payload: str = ""
    timestamp: float = 0.0
    nonce: str = ""
    hmac: str = ""
    signature: str = ""
    version: str = PROTOCOL_VERSION
    
    def __post_init__(self):
        """
        Called automatically after __init__.
        Sets timestamp if not provided.
        """
        # LEARN: __post_init__ runs after the dataclass creates the object
        # LEARN: We use it to set default values that require computation
        
        if self.timestamp == 0.0:
            self.timestamp = get_timestamp()
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the message to a dictionary.
        
        Returns:
            Dictionary representation of the message
        """
        # LEARN: We need to convert the MessageType enum to a string
        # LEARN: because JSON doesn't know how to serialize enum objects
        
        data = asdict(self)
        data['msg_type'] = self.msg_type.name  # Convert enum to string
        return data
    
    def to_json(self) -> str:
        """
        Serialize the message to a JSON string.
        
        Returns:
            JSON string representation of the message
        """
        # LEARN: JSON (JavaScript Object Notation) is a standard text format
        # LEARN: for data exchange. It's human-readable and widely supported.
        
        return json.dumps(self.to_dict())
    
    def to_bytes(self) -> bytes:
        """
        Serialize the message to bytes for network transmission.
        
        Returns:
            UTF-8 encoded bytes of the JSON message
        """
        return self.to_json().encode(TEXT_ENCODING)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Message':
        """
        Create a Message object from a dictionary.
        
        Args:
            data: Dictionary containing message fields
            
        Returns:
            Message object
        """
        # LEARN: @classmethod means this method belongs to the class, not instances
        # LEARN: 'cls' refers to the Message class itself
        # LEARN: This is a "factory method" pattern for creating objects
        
        # Convert string back to MessageType enum
        data['msg_type'] = MessageType[data['msg_type']]
        return cls(**data)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'Message':
        """
        Deserialize a Message from a JSON string.
        
        Args:
            json_str: JSON string representation of a message
            
        Returns:
            Message object
        """
        data = json.loads(json_str)
        return cls.from_dict(data)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'Message':
        """
        Deserialize a Message from bytes.
        
        Args:
            data: UTF-8 encoded bytes of a JSON message
            
        Returns:
            Message object
        """
        json_str = data.decode(TEXT_ENCODING)
        return cls.from_json(json_str)


# =============================================================================
# MESSAGE FACTORY FUNCTIONS
# =============================================================================
# LEARN: Factory functions create pre-configured Message objects
# LEARN: This makes the code cleaner and reduces repetition

def create_register_message(username: str) -> Message:
    """
    Create a registration request message.
    
    Args:
        username: Desired username for registration
        
    Returns:
        Message object for registration
    """
    return Message(
        msg_type=MessageType.REGISTER,
        sender=username,
        payload=username
    )


def create_register_ack_message(username: str) -> Message:
    """
    Create a registration acknowledgment message.
    
    Args:
        username: Registered username
        
    Returns:
        Message object acknowledging registration
    """
    return Message(
        msg_type=MessageType.REGISTER_ACK,
        sender="SERVER",
        recipient=username,
        payload=f"Registration successful for {username}"
    )


def create_register_fail_message(username: str, reason: str) -> Message:
    """
    Create a registration failure message.
    
    Args:
        username: Username that failed to register
        reason: Reason for failure
        
    Returns:
        Message object indicating failure
    """
    return Message(
        msg_type=MessageType.REGISTER_FAIL,
        sender="SERVER",
        recipient=username,
        payload=reason
    )


def create_chat_message(sender: str, recipient: str, content: str) -> Message:
    """
    Create a chat message to send to another user.
    
    Args:
        sender: Username of sender
        recipient: Username of recipient
        content: Message content (will be encrypted before sending)
        
    Returns:
        Message object for the chat message
    """
    return Message(
        msg_type=MessageType.SEND_MESSAGE,
        sender=sender,
        recipient=recipient,
        payload=content
    )


def create_user_list_request(username: str) -> Message:
    """
    Create a request for the list of online users.
    
    Args:
        username: Username of the requester
        
    Returns:
        Message object requesting user list
    """
    return Message(
        msg_type=MessageType.LIST_USERS,
        sender=username
    )


def create_user_list_response(users: list) -> Message:
    """
    Create a response containing the list of online users.
    
    Args:
        users: List of online usernames
        
    Returns:
        Message object containing user list
    """
    return Message(
        msg_type=MessageType.USER_LIST,
        sender="SERVER",
        payload=json.dumps(users)  # Serialize list as JSON string
    )


def create_error_message(recipient: str, error_text: str) -> Message:
    """
    Create an error message.
    
    Args:
        recipient: Username to receive the error
        error_text: Description of the error
        
    Returns:
        Message object containing error information
    """
    return Message(
        msg_type=MessageType.ERROR,
        sender="SERVER",
        recipient=recipient,
        payload=error_text
    )


def create_disconnect_message(username: str) -> Message:
    """
    Create a disconnect notification message.
    
    Args:
        username: Username of the disconnecting user
        
    Returns:
        Message object indicating disconnection
    """
    return Message(
        msg_type=MessageType.DISCONNECT,
        sender=username
    )


def create_user_joined_message(username: str) -> Message:
    """
    Create a notification that a user has joined.
    
    Args:
        username: Username of the user who joined
        
    Returns:
        Message object for broadcast
    """
    return Message(
        msg_type=MessageType.USER_JOINED,
        sender="SERVER",
        payload=username
    )


def create_user_left_message(username: str) -> Message:
    """
    Create a notification that a user has left.
    
    Args:
        username: Username of the user who left
        
    Returns:
        Message object for broadcast
    """
    return Message(
        msg_type=MessageType.USER_LEFT,
        sender="SERVER",
        payload=username
    )


def create_key_exchange_message(username: str, public_key_pem: str) -> Message:
    """
    Create a key exchange message containing the client's public key.
    
    Args:
        username: Username of the client
        public_key_pem: PEM-encoded public key
        
    Returns:
        Message object for key exchange
    """
    return Message(
        msg_type=MessageType.KEY_EXCHANGE,
        sender=username,
        payload=public_key_pem
    )


def create_session_key_message(
    recipient: str,
    encrypted_session_key: str,
    nonce: str
) -> Message:
    """
    Create a message containing the encrypted session key.
    
    Args:
        recipient: Username to receive the session key
        encrypted_session_key: Session key encrypted with recipient's public key
        nonce: Nonce used for this session
        
    Returns:
        Message object containing encrypted session key
    """
    # LEARN: The session key is encrypted with the recipient's public key
    # LEARN: Only they can decrypt it with their private key
    # LEARN: This is how we securely share the symmetric (AES) key
    
    return Message(
        msg_type=MessageType.SESSION_KEY,
        sender="SERVER",
        recipient=recipient,
        payload=encrypted_session_key,
        nonce=nonce
    )


# =============================================================================
# MESSAGE VALIDATION
# =============================================================================

def validate_message(message: Message) -> tuple[bool, str]:
    """
    Validate a message for required fields and format.
    
    Args:
        message: Message object to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    # LEARN: Input validation is crucial for security
    # LEARN: Never trust data from the network - always validate it
    
    # Check required fields
    if not message.sender:
        return False, "Message missing sender field"
    
    if not isinstance(message.msg_type, MessageType):
        return False, "Invalid message type"
    
    # Check protocol version
    if message.version != PROTOCOL_VERSION:
        return False, f"Protocol version mismatch: expected {PROTOCOL_VERSION}, got {message.version}"
    
    # Check timestamp is reasonable (not more than 5 minutes old or in future)
    from src.utils.constants import MAX_MESSAGE_AGE
    from src.utils.helpers import is_timestamp_valid
    
    if not is_timestamp_valid(message.timestamp, MAX_MESSAGE_AGE):
        return False, "Message timestamp is invalid or expired"
    
    return True, ""


# =============================================================================
# PROTOCOL UTILITIES
# =============================================================================

def parse_user_list(payload: str) -> list:
    """
    Parse a user list from a message payload.
    
    Args:
        payload: JSON-encoded list of usernames
        
    Returns:
        List of usernames
    """
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return []


def get_message_type_name(msg_type: MessageType) -> str:
    """
    Get a human-readable name for a message type.
    
    Args:
        msg_type: MessageType enum value
        
    Returns:
        Human-readable string
    """
    # LEARN: This is useful for logging and debugging
    
    names = {
        MessageType.REGISTER: "Registration Request",
        MessageType.REGISTER_ACK: "Registration Acknowledged",
        MessageType.REGISTER_FAIL: "Registration Failed",
        MessageType.KEY_EXCHANGE: "Key Exchange",
        MessageType.KEY_EXCHANGE_ACK: "Key Exchange Acknowledged",
        MessageType.SESSION_KEY: "Session Key",
        MessageType.SEND_MESSAGE: "Send Message",
        MessageType.RECEIVE_MESSAGE: "Receive Message",
        MessageType.MESSAGE_ACK: "Message Acknowledged",
        MessageType.FETCH_MESSAGES: "Fetch Messages",
        MessageType.MESSAGE_LIST: "Message List",
        MessageType.LIST_USERS: "List Users Request",
        MessageType.USER_LIST: "User List",
        MessageType.USER_JOINED: "User Joined",
        MessageType.USER_LEFT: "User Left",
        MessageType.DISCONNECT: "Disconnect",
        MessageType.PING: "Ping",
        MessageType.PONG: "Pong",
        MessageType.ERROR: "Error"
    }
    
    return names.get(msg_type, "Unknown")
