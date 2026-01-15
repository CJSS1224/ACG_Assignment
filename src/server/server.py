"""
Server Module - Member 1: [Name]

This module implements the secure messaging server that:
- Accepts client connections via TCP sockets
- Handles client registration and authentication
- Routes encrypted messages between clients
- Stores messages securely (encrypted at rest with signatures)

The server is the central hub of the messaging system. All messages
pass through it, and it maintains the public keys of all registered clients.

Security Features:
- All messages are encrypted (AES-256)
- Message integrity verified (HMAC-SHA256)
- Non-repudiation via digital signatures (RSA)
- Certificate-based client identification

Usage:
    python -m src.server.server

Dependencies:
    - All crypto modules (encryption, integrity, signatures)
    - PKI module for key management
"""

import socket
import threading
import json
import os
from typing import Dict, Optional, Tuple
from datetime import datetime

from src.utils.constants import (
    SERVER_HOST,
    SERVER_PORT,
    BUFFER_SIZE,
    MAX_PENDING_CONNECTIONS,
    MESSAGES_DIR,
    SERVER_LOG_FILE
)
from src.utils.helpers import (
    setup_logger,
    ensure_directory_exists,
    bytes_to_base64,
    base64_to_bytes,
    get_timestamp
)
from src.utils.protocol import (
    Message,
    MessageType,
    create_register_ack_message,
    create_register_fail_message,
    create_user_list_response,
    create_error_message,
    create_user_joined_message,
    create_user_left_message
)
from src.crypto.encryption import (
    generate_aes_key,
    encrypt_message,
    decrypt_message,
    encrypt_for_storage
)
from src.crypto.integrity import (
    generate_hmac_key,
    generate_hmac_string,
    verify_hmac_string,
    create_integrity_data,
    verify_integrity_data,
    clear_nonce_cache
)
from src.crypto.signatures import (
    verify_signature_string,
    create_signed_package
)
from src.pki.key_management import (
    initialize_ca,
    setup_client_keys,
    client_keys_exist,
    load_certificate,
    load_public_key,
    get_client_key_paths,
    generate_session_key,
    encrypt_session_key,
    pem_string_to_public_key,
    public_key_to_pem_string
)

# Set up logger
logger = setup_logger(__name__, SERVER_LOG_FILE)


class ClientConnection:
    """
    Represents a connected client.
    
    Stores all information about a single client connection including
    their socket, username, keys, and session information.
    """
    
    def __init__(self, socket: socket.socket, address: tuple):
        """
        Initialize a new client connection.
        
        Args:
            socket: The client's socket object
            address: Tuple of (ip, port)
        """
        self.socket = socket
        self.address = address
        self.username: Optional[str] = None
        self.public_key = None  # RSA public key
        self.session_key: Optional[bytes] = None  # AES session key
        self.hmac_key: Optional[bytes] = None  # HMAC key for this session
        self.is_authenticated = False
    
    def __repr__(self):
        return f"ClientConnection({self.username}@{self.address})"


class SecureServer:
    """
    The main secure messaging server.
    
    This class manages all client connections, handles message routing,
    and ensures all cryptographic operations are performed correctly.
    """
    
    def __init__(self, host: str = SERVER_HOST, port: int = SERVER_PORT):
        """
        Initialize the server.
        
        Args:
            host: IP address to bind to
            port: Port number to listen on
        """
        # LEARN: Server initialization sets up all the components needed
        # LEARN: before accepting any connections
        
        self.host = host
        self.port = port
        self.socket: Optional[socket.socket] = None
        self.running = False
        
        # Connected clients dictionary: username -> ClientConnection
        # LEARN: We use a dictionary for O(1) lookup by username
        self.clients: Dict[str, ClientConnection] = {}
        
        # Lock for thread-safe access to shared resources
        # LEARN: Multiple threads access self.clients simultaneously
        # LEARN: The lock prevents race conditions
        self.clients_lock = threading.Lock()
        
        # Initialize CA and load server keys
        # LEARN: The CA is needed to issue certificates to new clients
        self.ca_private_key, self.ca_certificate = initialize_ca()
        
        # Master key for server-side encryption (at-rest)
        # LEARN: This key encrypts messages stored on the server
        # LEARN: In production, this would be loaded from secure storage
        self.storage_key = generate_aes_key()
        
        logger.info("Server initialized")
    
    def start(self) -> None:
        """
        Start the server and begin accepting connections.
        """
        # LEARN: Socket server startup sequence:
        # LEARN: 1. Create socket
        # LEARN: 2. Set options (SO_REUSEADDR allows quick restart)
        # LEARN: 3. Bind to address
        # LEARN: 4. Listen for connections
        # LEARN: 5. Accept loop
        
        # Create TCP socket
        # LEARN: AF_INET = IPv4, SOCK_STREAM = TCP
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Allow address reuse (helpful during development)
        # LEARN: Without this, you get "Address already in use" error
        # LEARN: if you restart the server quickly
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Bind to address
        self.socket.bind((self.host, self.port))
        
        # Start listening
        self.socket.listen(MAX_PENDING_CONNECTIONS)
        self.running = True
        
        logger.info(f"Server started on {self.host}:{self.port}")
        print(f"\n[SERVER] Listening on {self.host}:{self.port}")
        print("[SERVER] Press Ctrl+C to stop\n")
        
        # Accept connections in a loop
        self._accept_connections()
    
    def _accept_connections(self) -> None:
        """
        Main loop that accepts incoming client connections.
        """
        while self.running:
            try:
                # LEARN: accept() blocks until a client connects
                # LEARN: Returns a new socket for that specific client
                client_socket, address = self.socket.accept()
                
                logger.info(f"New connection from {address}")
                print(f"[SERVER] New connection from {address}")
                
                # Create client connection object
                client = ClientConnection(client_socket, address)
                
                # Handle client in a new thread
                # LEARN: Each client gets its own thread so the server
                # LEARN: can handle multiple clients simultaneously
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client,),
                    daemon=True  # Thread dies when main program exits
                )
                client_thread.start()
                
            except Exception as e:
                if self.running:
                    logger.error(f"Error accepting connection: {e}")
    
    def _handle_client(self, client: ClientConnection) -> None:
        """
        Handle all communication with a single client.
        
        This runs in a separate thread for each connected client.
        
        Args:
            client: The client connection to handle
        """
        try:
            while self.running:
                # Receive data from client
                data = client.socket.recv(BUFFER_SIZE)
                
                if not data:
                    # Client disconnected
                    break
                
                # Parse the message
                try:
                    message = Message.from_bytes(data)
                    self._process_message(client, message)
                    
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid message format from {client.address}: {e}")
                    self._send_error(client, "Invalid message format")
                    
        except ConnectionResetError:
            logger.info(f"Client {client.address} disconnected abruptly")
            
        except Exception as e:
            logger.error(f"Error handling client {client.address}: {e}")
            
        finally:
            # Clean up when client disconnects
            self._remove_client(client)
    
    def _process_message(self, client: ClientConnection, message: Message) -> None:
        """
        Process a received message based on its type.
        
        Args:
            client: The client who sent the message
            message: The message to process
        """
        # LEARN: Message routing - different message types need different handling
        # LEARN: This is like a dispatcher that sends each message to the right handler
        
        msg_type = message.msg_type
        
        if msg_type == MessageType.REGISTER:
            self._handle_registration(client, message)
            
        elif msg_type == MessageType.KEY_EXCHANGE:
            self._handle_key_exchange(client, message)
            
        elif msg_type == MessageType.SEND_MESSAGE:
            self._handle_send_message(client, message)
            
        elif msg_type == MessageType.LIST_USERS:
            self._handle_list_users(client)
            
        elif msg_type == MessageType.GET_PUBLIC_KEY:
            self._handle_get_public_key(client, message)
            
        elif msg_type == MessageType.DISCONNECT:
            self._remove_client(client)
            
        else:
            logger.warning(f"Unknown message type: {msg_type}")
    
    def _handle_registration(self, client: ClientConnection, message: Message) -> None:
        """
        Handle client registration.
        
        Args:
            client: The client attempting to register
            message: Registration message with desired username
        """
        username = message.payload.strip()
        
        logger.info(f"Registration attempt: {username} from {client.address}")
        
        # Validate username
        if not username or len(username) < 3:
            response = create_register_fail_message(username, "Username too short (min 3 chars)")
            self._send_message(client, response)
            return
        
        # Check if username is taken
        with self.clients_lock:
            if username in self.clients:
                response = create_register_fail_message(username, "Username already taken")
                self._send_message(client, response)
                return
            
            # Register the client
            client.username = username
            self.clients[username] = client
        
        # Generate session keys for this client
        client.session_key = generate_session_key()
        client.hmac_key = generate_hmac_key()
        
        # Send success response
        response = create_register_ack_message(username)
        self._send_message(client, response)
        
        logger.info(f"Client registered: {username}")
        print(f"[SERVER] User '{username}' registered")
        
        # Notify other clients
        self._broadcast_user_joined(username)
    
    def _handle_key_exchange(self, client: ClientConnection, message: Message) -> None:
        """
        Handle public key exchange from client.
        
        The client sends their public key, and we store it for future
        signature verification and encrypted communication.
        
        Args:
            client: The client sending their key
            message: Message containing PEM-encoded public key
        """
        if not client.username:
            self._send_error(client, "Must register before key exchange")
            return
        
        try:
            # Parse the public key from PEM format
            public_key_pem = message.payload
            client.public_key = pem_string_to_public_key(public_key_pem)
            
            logger.info(f"Received public key from {client.username}")
            
            # Send acknowledgment with session key (encrypted with client's public key)
            # LEARN: We encrypt the session key with the client's public key
            # LEARN: Only they can decrypt it with their private key
            encrypted_session_key = encrypt_session_key(
                client.session_key,
                client.public_key
            )
            
            # Also send the HMAC key
            encrypted_hmac_key = encrypt_session_key(
                client.hmac_key,
                client.public_key
            )
            
            # Create response with both keys
            response = Message(
                msg_type=MessageType.KEY_EXCHANGE_ACK,
                sender="SERVER",
                recipient=client.username,
                payload=json.dumps({
                    'session_key': bytes_to_base64(encrypted_session_key),
                    'hmac_key': bytes_to_base64(encrypted_hmac_key)
                })
            )
            self._send_message(client, response)
            
            client.is_authenticated = True
            logger.info(f"Key exchange complete with {client.username}")
            print(f"[SERVER] Key exchange complete with '{client.username}'")
            
        except Exception as e:
            logger.error(f"Key exchange failed for {client.username}: {e}")
            self._send_error(client, f"Key exchange failed: {str(e)}")
    
    def _handle_send_message(self, client: ClientConnection, message: Message) -> None:
        """
        Handle a message being sent from one client to another.
        
        The message should be encrypted and signed by the sender.
        We verify the signature and forward to the recipient.
        
        Args:
            client: The sender
            message: The message to deliver
        """
        if not client.is_authenticated:
            self._send_error(client, "Must complete key exchange first")
            return
        
        recipient_username = message.recipient
        
        # Check if recipient exists and is online
        with self.clients_lock:
            recipient = self.clients.get(recipient_username)
        
        if not recipient:
            self._send_error(client, f"User '{recipient_username}' not found or offline")
            return
        
        # Verify the message signature if present
        if message.signature and client.public_key:
            # LEARN: Verify the sender actually signed this message
            # LEARN: This provides non-repudiation
            signature_valid = verify_signature_string(
                message.payload,
                message.signature,
                client.public_key
            )
            if not signature_valid:
                logger.warning(f"Invalid signature from {client.username}")
                self._send_error(client, "Invalid message signature")
                return
        
        # Verify integrity (HMAC)
        if message.hmac and client.hmac_key:
            hmac_valid = verify_hmac_string(
                message.payload,
                message.hmac,
                client.hmac_key
            )
            if not hmac_valid:
                logger.warning(f"HMAC verification failed for message from {client.username}")
                self._send_error(client, "Message integrity check failed")
                return
        
        logger.info(f"Message from {client.username} to {recipient_username}")
        
        # Store message (encrypted at rest)
        self._store_message(client.username, recipient_username, message)
        
        # Forward to recipient
        forward_message = Message(
            msg_type=MessageType.RECEIVE_MESSAGE,
            sender=client.username,
            recipient=recipient_username,
            payload=message.payload,  # Still encrypted
            timestamp=message.timestamp,
            nonce=message.nonce,
            signature=message.signature  # Include original signature
        )
        
        self._send_message(recipient, forward_message)
        
        # Send acknowledgment to sender
        ack = Message(
            msg_type=MessageType.MESSAGE_ACK,
            sender="SERVER",
            recipient=client.username,
            payload=f"Message delivered to {recipient_username}"
        )
        self._send_message(client, ack)
    
    def _handle_list_users(self, client: ClientConnection) -> None:
        """
        Send list of online users to a client.
        
        Args:
            client: The client requesting the list
        """
        with self.clients_lock:
            # Get all usernames except the requester
            users = [u for u in self.clients.keys() if u != client.username]
        
        response = create_user_list_response(users)
        self._send_message(client, response)
    
    def _handle_get_public_key(self, client: ClientConnection, message: Message) -> None:
        """
        Handle a request for another user's public key.
        
        This enables end-to-end encryption between clients.
        
        Args:
            client: The client requesting the public key
            message: Message containing the target username
        """
        target_username = message.payload.strip()
        
        logger.info(f"{client.username} requesting public key for {target_username}")
        
        # Look up the target user
        with self.clients_lock:
            target_client = self.clients.get(target_username)
        
        if not target_client:
            # User not found or offline
            response = Message(
                msg_type=MessageType.PUBLIC_KEY_RESPONSE,
                sender="SERVER",
                recipient=client.username,
                payload=f"ERROR: User '{target_username}' not found or offline"
            )
            self._send_message(client, response)
            return
        
        if not target_client.public_key:
            # User hasn't completed key exchange
            response = Message(
                msg_type=MessageType.PUBLIC_KEY_RESPONSE,
                sender="SERVER",
                recipient=client.username,
                payload=f"ERROR: User '{target_username}' has not completed key exchange"
            )
            self._send_message(client, response)
            return
        
        # Send the public key
        # LEARN: We send the public key in PEM format
        # LEARN: This allows the requesting client to encrypt messages for the target
        public_key_pem = public_key_to_pem_string(target_client.public_key)
        
        response = Message(
            msg_type=MessageType.PUBLIC_KEY_RESPONSE,
            sender="SERVER",
            recipient=client.username,
            payload=public_key_pem
        )
        self._send_message(client, response)
        
        logger.info(f"Sent {target_username}'s public key to {client.username}")
    
    def _store_message(self, sender: str, recipient: str, message: Message) -> None:
        """
        Store a message securely (encrypted at rest).
        
        Args:
            sender: Username of sender
            recipient: Username of recipient
            message: The message to store
        """
        # LEARN: At-rest encryption protects stored messages
        # LEARN: Even if someone accesses the storage, they can't read messages
        
        ensure_directory_exists(MESSAGES_DIR)
        
        # Create storage record
        storage_record = {
            'sender': sender,
            'recipient': recipient,
            'encrypted_payload': message.payload,  # Already encrypted by client
            'timestamp': message.timestamp,
            'signature': message.signature,  # Preserve for non-repudiation
            'stored_at': get_timestamp()
        }
        
        # Encrypt the storage record itself
        record_json = json.dumps(storage_record)
        encrypted_record = encrypt_for_storage(record_json, self.storage_key)
        
        # Save to file
        filename = f"{sender}_to_{recipient}_{int(message.timestamp)}.json"
        filepath = os.path.join(MESSAGES_DIR, filename)
        
        with open(filepath, 'w') as f:
            json.dump(encrypted_record, f)
        
        logger.debug(f"Message stored: {filename}")
    
    def _send_message(self, client: ClientConnection, message: Message) -> None:
        """
        Send a message to a client.
        
        Args:
            client: The client to send to
            message: The message to send
        """
        try:
            data = message.to_bytes()
            client.socket.sendall(data)
        except Exception as e:
            logger.error(f"Error sending to {client.username}: {e}")
    
    def _send_error(self, client: ClientConnection, error_text: str) -> None:
        """
        Send an error message to a client.
        
        Args:
            client: The client to send to
            error_text: Description of the error
        """
        username = client.username or "unknown"
        error_msg = create_error_message(username, error_text)
        self._send_message(client, error_msg)
    
    def _broadcast_user_joined(self, username: str) -> None:
        """
        Notify all clients that a user has joined.
        
        Args:
            username: The user who joined
        """
        notification = create_user_joined_message(username)
        
        with self.clients_lock:
            for other_username, client in self.clients.items():
                if other_username != username:
                    self._send_message(client, notification)
    
    def _broadcast_user_left(self, username: str) -> None:
        """
        Notify all clients that a user has left.
        
        Args:
            username: The user who left
        """
        notification = create_user_left_message(username)
        
        with self.clients_lock:
            for other_username, client in self.clients.items():
                if other_username != username:
                    self._send_message(client, notification)
    
    def _remove_client(self, client: ClientConnection) -> None:
        """
        Remove a client from the server.
        
        Args:
            client: The client to remove
        """
        username = client.username
        
        # Close socket
        try:
            client.socket.close()
        except:
            pass
        
        # Remove from clients dict
        if username:
            with self.clients_lock:
                if username in self.clients:
                    del self.clients[username]
            
            logger.info(f"Client disconnected: {username}")
            print(f"[SERVER] User '{username}' disconnected")
            
            # Notify others
            self._broadcast_user_left(username)
    
    def stop(self) -> None:
        """Stop the server and disconnect all clients."""
        logger.info("Server shutting down...")
        print("\n[SERVER] Shutting down...")
        
        self.running = False
        
        # Close all client connections
        with self.clients_lock:
            for client in list(self.clients.values()):
                try:
                    client.socket.close()
                except:
                    pass
            self.clients.clear()
        
        # Close server socket
        if self.socket:
            self.socket.close()
        
        logger.info("Server stopped")
        print("[SERVER] Stopped")


def main():
    """Main entry point for the server."""
    print("\n" + "=" * 60)
    print(" ST2504 Applied Cryptography - Secure Messaging Server")
    print("=" * 60 + "\n")
    
    server = SecureServer()
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[SERVER] Interrupt received")
    except Exception as e:
        logger.error(f"Server error: {e}")
        print(f"[SERVER] Error: {e}")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
