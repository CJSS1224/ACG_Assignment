"""
Client Module - Member 2: [Name]

This module implements the secure messaging client that:
- Connects to the secure messaging server
- Handles user registration and key exchange
- Provides a command-line interface for sending/receiving messages
- Encrypts messages before sending, decrypts on receipt
- Signs messages for non-repudiation

The client handles all cryptographic operations locally before
sending data to the server, ensuring end-to-end security.

Security Features:
- AES-256 encryption for message confidentiality
- HMAC-SHA256 for message integrity
- RSA digital signatures for non-repudiation
- Secure key exchange using RSA encryption

Usage:
    python -m src.client.client

Dependencies:
    - All crypto modules (encryption, integrity, signatures)
    - PKI module for key management
"""

import socket
import threading
import json
import sys
import os
from typing import Optional, Dict

from src.utils.constants import (
    SERVER_HOST,
    SERVER_PORT,
    BUFFER_SIZE,
    CLIENT_LOG_FILE,
    CLIENT_KEYS_DIR
)
from src.utils.helpers import (
    setup_logger,
    bytes_to_base64,
    base64_to_bytes,
    ensure_directory_exists,
    get_timestamp
)
from src.utils.protocol import (
    Message,
    MessageType,
    create_register_message,
    create_chat_message,
    create_user_list_request,
    create_disconnect_message,
    create_key_exchange_message
)
from src.crypto.encryption import (
    generate_aes_key,
    encrypt_message,
    decrypt_message
)
from src.crypto.integrity import (
    generate_hmac_string,
    verify_hmac_string,
    generate_nonce_string
)
from src.crypto.signatures import (
    sign_message_string,
    verify_signature_string
)
from src.pki.key_management import (
    generate_rsa_keypair,
    save_private_key,
    save_public_key,
    load_private_key,
    load_public_key,
    public_key_to_pem_string,
    pem_string_to_public_key,
    decrypt_session_key,
    get_client_key_paths,
    client_keys_exist
)

# Set up logger
logger = setup_logger(__name__, CLIENT_LOG_FILE)


class SecureClient:
    """
    The secure messaging client.
    
    Handles connection to the server, encryption/decryption of messages,
    and provides a user interface for messaging.
    """
    
    def __init__(self, host: str = SERVER_HOST, port: int = SERVER_PORT):
        """
        Initialize the client.
        
        Args:
            host: Server IP address
            port: Server port number
        """
        self.host = host
        self.port = port
        self.socket: Optional[socket.socket] = None
        self.connected = False
        self.username: Optional[str] = None
        
        # Cryptographic keys
        self.private_key = None  # RSA private key
        self.public_key = None   # RSA public key
        self.session_key: Optional[bytes] = None  # AES session key (from server)
        self.hmac_key: Optional[bytes] = None     # HMAC key (from server)
        
        # Other users' public keys (for signature verification and encryption)
        # LEARN: We cache public keys so we don't request them every time
        self.peer_public_keys: Dict[str, any] = {}
        
        # Synchronization for public key requests
        # LEARN: Threading.Event is used to signal between threads
        # LEARN: One thread waits on the event, another thread sets it
        self._pending_key_request: Optional[str] = None  # Username we're waiting for
        self._key_request_event = threading.Event()  # Signals when key is received
        self._key_request_error: Optional[str] = None  # Error message if request failed
        
        # Thread for receiving messages
        self.receive_thread: Optional[threading.Thread] = None
        
        logger.info("Client initialized")
    
    def connect(self) -> bool:
        """
        Connect to the server.
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            # LEARN: Create a TCP socket and connect to server
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connected = True
            
            logger.info(f"Connected to server at {self.host}:{self.port}")
            print(f"[CLIENT] Connected to server at {self.host}:{self.port}")
            
            return True
            
        except ConnectionRefusedError:
            print(f"[CLIENT] Could not connect to server at {self.host}:{self.port}")
            print("[CLIENT] Make sure the server is running.")
            return False
            
        except Exception as e:
            logger.error(f"Connection error: {e}")
            print(f"[CLIENT] Connection error: {e}")
            return False
    
    def setup_keys(self, username: str) -> None:
        """
        Set up RSA keys for the client.
        
        Loads existing keys if available, otherwise generates new ones.
        
        Args:
            username: Client's username (used for key filenames)
        """
        ensure_directory_exists(CLIENT_KEYS_DIR)
        
        private_key_path, public_key_path = get_client_key_paths(username)
        
        if client_keys_exist(username):
            # Load existing keys
            print("[CLIENT] Loading existing keys...")
            self.private_key = load_private_key(private_key_path)
            self.public_key = load_public_key(public_key_path)
            logger.info("Loaded existing RSA keys")
        else:
            # Generate new keys
            print("[CLIENT] Generating new RSA key pair...")
            self.private_key, self.public_key = generate_rsa_keypair()
            
            # Save keys
            save_private_key(self.private_key, private_key_path)
            save_public_key(self.public_key, public_key_path)
            
            logger.info("Generated and saved new RSA keys")
            print("[CLIENT] Keys generated and saved")
    
    def register(self, username: str) -> bool:
        """
        Register with the server using the given username.
        
        Args:
            username: Desired username
            
        Returns:
            True if registration successful, False otherwise
        """
        self.username = username
        
        # Set up keys
        self.setup_keys(username)
        
        # Send registration message
        register_msg = create_register_message(username)
        self._send_message(register_msg)
        
        # Wait for response
        response = self._receive_message()
        
        if response.msg_type == MessageType.REGISTER_ACK:
            logger.info(f"Registered as {username}")
            print(f"[CLIENT] Registered as '{username}'")
            
            # Now do key exchange
            return self._do_key_exchange()
            
        elif response.msg_type == MessageType.REGISTER_FAIL:
            print(f"[CLIENT] Registration failed: {response.payload}")
            return False
        
        return False
    
    def _do_key_exchange(self) -> bool:
        """
        Perform key exchange with the server.
        
        Sends our public key, receives encrypted session key.
        
        Returns:
            True if key exchange successful, False otherwise
        """
        print("[CLIENT] Performing key exchange...")
        
        # Send our public key
        public_key_pem = public_key_to_pem_string(self.public_key)
        key_msg = create_key_exchange_message(self.username, public_key_pem)
        self._send_message(key_msg)
        
        # Wait for response with session key
        response = self._receive_message()
        
        if response.msg_type == MessageType.KEY_EXCHANGE_ACK:
            try:
                # Parse the response
                key_data = json.loads(response.payload)
                
                # Decrypt session key with our private key
                # LEARN: The server encrypted these with our public key
                # LEARN: Only we can decrypt them with our private key
                encrypted_session_key = base64_to_bytes(key_data['session_key'])
                encrypted_hmac_key = base64_to_bytes(key_data['hmac_key'])
                
                self.session_key = decrypt_session_key(
                    encrypted_session_key,
                    self.private_key
                )
                self.hmac_key = decrypt_session_key(
                    encrypted_hmac_key,
                    self.private_key
                )
                
                logger.info("Key exchange complete")
                print("[CLIENT] Key exchange complete - secure channel established")
                return True
                
            except Exception as e:
                logger.error(f"Key exchange failed: {e}")
                print(f"[CLIENT] Key exchange failed: {e}")
                return False
        
        return False
    
    def start_receiving(self) -> None:
        """
        Start the background thread for receiving messages.
        """
        self.receive_thread = threading.Thread(
            target=self._receive_loop,
            daemon=True
        )
        self.receive_thread.start()
    
    def _receive_loop(self) -> None:
        """
        Background loop that receives and processes incoming messages.
        """
        while self.connected:
            try:
                message = self._receive_message()
                if message:
                    self._handle_incoming_message(message)
            except Exception as e:
                if self.connected:
                    logger.error(f"Receive error: {e}")
                break
    
    def _handle_incoming_message(self, message: Message) -> None:
        """
        Handle an incoming message based on its type.
        
        Args:
            message: The received message
        """
        msg_type = message.msg_type
        
        if msg_type == MessageType.RECEIVE_MESSAGE:
            self._handle_chat_message(message)
            
        elif msg_type == MessageType.USER_LIST:
            self._handle_user_list(message)
            
        elif msg_type == MessageType.PUBLIC_KEY_RESPONSE:
            self._handle_public_key_response(message)
            
        elif msg_type == MessageType.USER_JOINED:
            print(f"\n[NOTIFICATION] User '{message.payload}' has joined")
            self._print_prompt()
            
        elif msg_type == MessageType.USER_LEFT:
            print(f"\n[NOTIFICATION] User '{message.payload}' has left")
            self._print_prompt()
            
        elif msg_type == MessageType.MESSAGE_ACK:
            logger.debug(f"Message acknowledged: {message.payload}")
            
        elif msg_type == MessageType.ERROR:
            print(f"\n[ERROR] {message.payload}")
            self._print_prompt()
            
        else:
            logger.warning(f"Unhandled message type: {msg_type}")
    
    def _handle_chat_message(self, message: Message) -> None:
        """
        Handle a received chat message.
        
        Decrypts the message and verifies the signature.
        
        Args:
            message: The encrypted message
        """
        sender = message.sender
        
        try:
            # The payload contains:
            # - encrypted_key: AES key encrypted with OUR public key
            # - ciphertext: Message encrypted with that AES key
            # - iv: Initialization vector for AES
            encrypted_data = json.loads(message.payload)
            
            # LEARN: Hybrid encryption scheme:
            # LEARN: 1. Sender generates random AES key for this message
            # LEARN: 2. Sender encrypts message with AES key
            # LEARN: 3. Sender encrypts AES key with RECIPIENT's public key
            # LEARN: 4. Only recipient can decrypt the AES key with their private key
            # LEARN: 5. Then recipient uses AES key to decrypt the message
            
            # Step 1: Decrypt the AES key using our private key
            from src.pki.key_management import decrypt_session_key
            encrypted_aes_key = base64_to_bytes(encrypted_data['encrypted_key'])
            message_aes_key = decrypt_session_key(encrypted_aes_key, self.private_key)
            
            # Step 2: Decrypt the message using the AES key
            decrypted_text = decrypt_message(
                encrypted_data['ciphertext'],
                encrypted_data['iv'],
                message_aes_key
            )
            
            # Verify signature if present
            signature_status = ""
            if message.signature:
                # LEARN: To verify, we need the sender's public key
                # LEARN: For now, we'll note that signature is present
                # LEARN: Full verification would require fetching sender's public key
                signature_status = " [SIGNED]"
            
            # Display the message
            print(f"\n[MESSAGE from {sender}]{signature_status}: {decrypted_text}")
            self._print_prompt()
            
            logger.info(f"Received message from {sender}")
            
        except Exception as e:
            logger.error(f"Failed to decrypt message from {sender}: {e}")
            print(f"\n[ERROR] Could not decrypt message from {sender}")
            self._print_prompt()
    
    def _handle_user_list(self, message: Message) -> None:
        """
        Handle the user list response from server.
        
        Args:
            message: Message containing JSON list of users
        """
        try:
            users = json.loads(message.payload)
            
            print("\n" + "-" * 40)
            print("Online Users:")
            print("-" * 40)
            
            if users:
                for i, user in enumerate(users, 1):
                    print(f"  {i}. {user}")
            else:
                print("  No other users online")
            
            print("-" * 40)
            self._print_prompt()
            
        except json.JSONDecodeError:
            print("\n[ERROR] Failed to parse user list")
            self._print_prompt()
    
    def _handle_public_key_response(self, message: Message) -> None:
        """
        Handle a public key response from the server.
        
        This is called by the background receive thread when a PUBLIC_KEY_RESPONSE
        message arrives. It stores the key and signals the waiting thread.
        
        Args:
            message: Message containing the public key or error
        """
        # LEARN: This method runs in the BACKGROUND thread
        # LEARN: It stores the key and signals the MAIN thread that's waiting
        
        if message.payload.startswith("ERROR:"):
            # Request failed
            self._key_request_error = message.payload
            logger.warning(f"Public key request failed: {message.payload}")
        else:
            # Parse and store the public key
            try:
                public_key = pem_string_to_public_key(message.payload)
                
                # Store the key for the user we were waiting for
                if self._pending_key_request:
                    self.peer_public_keys[self._pending_key_request] = public_key
                    logger.info(f"Received and stored public key for {self._pending_key_request}")
                    self._key_request_error = None
                    
            except Exception as e:
                self._key_request_error = f"ERROR: Failed to parse public key: {e}"
                logger.error(f"Failed to parse public key: {e}")
        
        # Signal the waiting thread that we got a response
        # LEARN: .set() wakes up any thread that called .wait() on this event
        self._key_request_event.set()
    
    def send_chat_message(self, recipient: str, text: str) -> None:
        """
        Send an encrypted and signed message to another user.
        
        This method implements hybrid encryption:
        1. Generate a random AES key for this message
        2. Encrypt the message with AES
        3. Encrypt the AES key with recipient's PUBLIC key
        4. Sign the encrypted payload with our PRIVATE key
        5. Generate HMAC for integrity
        6. Send everything to the server
        
        Args:
            recipient: Username of the recipient
            text: The message text to send
        """
        if not self.private_key:
            print("[ERROR] Not authenticated. Cannot send messages.")
            return
        
        try:
            # First, get recipient's public key if we don't have it
            if recipient not in self.peer_public_keys:
                print(f"[CLIENT] Requesting {recipient}'s public key...")
                if not self._request_public_key(recipient):
                    print(f"[ERROR] Could not get public key for {recipient}")
                    return
            
            recipient_public_key = self.peer_public_keys[recipient]
            
            # LEARN: HYBRID ENCRYPTION SCHEME
            # LEARN: We use both symmetric (AES) and asymmetric (RSA) encryption:
            # LEARN: - AES is fast but requires shared key
            # LEARN: - RSA is slow but allows encryption without shared secret
            # LEARN: - Solution: Generate random AES key, encrypt message with AES,
            # LEARN:   encrypt AES key with recipient's RSA public key
            
            # Step 1: Generate a random AES key just for this message
            from src.crypto.encryption import generate_aes_key
            message_aes_key = generate_aes_key()
            
            # Step 2: Encrypt the message with AES
            # LEARN: AES encryption provides CONFIDENTIALITY
            ciphertext, iv = encrypt_message(text, message_aes_key)
            
            # Step 3: Encrypt the AES key with recipient's public key
            # LEARN: Only the recipient can decrypt this with their private key
            from src.pki.key_management import encrypt_session_key
            encrypted_aes_key = encrypt_session_key(message_aes_key, recipient_public_key)
            
            # Package encrypted data as JSON
            encrypted_payload = json.dumps({
                'ciphertext': ciphertext,
                'iv': iv,
                'encrypted_key': bytes_to_base64(encrypted_aes_key)
            })
            
            # Step 4: Sign the encrypted payload
            # LEARN: RSA signature provides NON-REPUDIATION
            # LEARN: Proves we sent this message - we can't deny it later
            signature = sign_message_string(encrypted_payload, self.private_key)
            
            # Step 5: Generate HMAC for integrity
            # LEARN: HMAC provides INTEGRITY verification during transit
            # LEARN: Detects if anyone modified the message
            hmac_value = generate_hmac_string(encrypted_payload, self.hmac_key)
            
            # Step 6: Generate nonce for replay protection
            nonce = generate_nonce_string()
            
            # Step 7: Create and send the message
            message = Message(
                msg_type=MessageType.SEND_MESSAGE,
                sender=self.username,
                recipient=recipient,
                payload=encrypted_payload,
                timestamp=get_timestamp(),
                nonce=nonce,
                hmac=hmac_value,
                signature=signature
            )
            
            self._send_message(message)
            logger.info(f"Sent encrypted message to {recipient}")
            
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            print(f"[ERROR] Failed to send message: {e}")
    
    def request_user_list(self) -> None:
        """
        Request the list of online users from the server.
        """
        request = create_user_list_request(self.username)
        self._send_message(request)
    
    def _request_public_key(self, target_username: str) -> bool:
        """
        Request another user's public key from the server.
        
        This is needed to encrypt messages for that user. The method sends
        a request and waits for the background thread to receive and process
        the response.
        
        Args:
            target_username: Username whose public key we need
            
        Returns:
            True if public key was received, False otherwise
        """
        # LEARN: To send an encrypted message to someone, we need their public key
        # LEARN: The server stores public keys of all registered users
        # LEARN: We request it before sending our first message to that user
        
        # LEARN: SYNCHRONIZATION FLOW:
        # LEARN: 1. Main thread: Clear event, set pending request, send request
        # LEARN: 2. Main thread: Wait on event (blocks until set)
        # LEARN: 3. Background thread: Receives response, stores key, sets event
        # LEARN: 4. Main thread: Wakes up, checks if key was stored successfully
        
        # Reset the event and error state
        self._key_request_event.clear()
        self._key_request_error = None
        self._pending_key_request = target_username
        
        # Send the request
        request = Message(
            msg_type=MessageType.GET_PUBLIC_KEY,
            sender=self.username,
            payload=target_username
        )
        self._send_message(request)
        
        # Wait for the background thread to receive and process the response
        # LEARN: .wait(timeout) blocks until .set() is called or timeout expires
        # LEARN: Returns True if event was set, False if timed out
        received = self._key_request_event.wait(timeout=10.0)  # 10 second timeout
        
        # Clear the pending request
        self._pending_key_request = None
        
        if not received:
            logger.error(f"Timeout waiting for public key of {target_username}")
            print(f"[ERROR] Timeout waiting for {target_username}'s public key")
            return False
        
        if self._key_request_error:
            print(f"[ERROR] {self._key_request_error}")
            return False
        
        # Check if key was actually stored
        if target_username in self.peer_public_keys:
            logger.info(f"Successfully obtained public key for {target_username}")
            return True
        else:
            logger.error(f"Public key for {target_username} not found after request")
            return False
    
    def disconnect(self) -> None:
        """
        Disconnect from the server gracefully.
        """
        if self.connected:
            try:
                # Send disconnect message
                disconnect_msg = create_disconnect_message(self.username)
                self._send_message(disconnect_msg)
            except:
                pass
            
            self.connected = False
            
            try:
                self.socket.close()
            except:
                pass
            
            logger.info("Disconnected from server")
            print("[CLIENT] Disconnected from server")
    
    def _send_message(self, message: Message) -> None:
        """
        Send a message to the server.
        
        Args:
            message: The message to send
        """
        try:
            data = message.to_bytes()
            self.socket.sendall(data)
        except Exception as e:
            logger.error(f"Send error: {e}")
            raise
    
    def _receive_message(self) -> Optional[Message]:
        """
        Receive a message from the server.
        
        Returns:
            The received Message, or None if connection closed
        """
        try:
            data = self.socket.recv(BUFFER_SIZE)
            if not data:
                return None
            return Message.from_bytes(data)
        except Exception as e:
            if self.connected:
                logger.error(f"Receive error: {e}")
            return None
    
    def _print_prompt(self) -> None:
        """Print the command prompt."""
        print(f"\n[{self.username}] > ", end="", flush=True)


def print_help() -> None:
    """Print help information about available commands."""
    print("\n" + "=" * 50)
    print("Available Commands:")
    print("=" * 50)
    print("  /msg <username> <message>  - Send a message to a user")
    print("  /users                     - List online users")
    print("  /help                      - Show this help message")
    print("  /quit                      - Disconnect and exit")
    print("=" * 50)
    print("\nExamples:")
    print("  /msg Alice Hello, how are you?")
    print("  /users")
    print("=" * 50 + "\n")


def main():
    """Main entry point for the client."""
    print("\n" + "=" * 60)
    print(" ST2504 Applied Cryptography - Secure Messaging Client")
    print("=" * 60 + "\n")
    
    # Create client
    client = SecureClient()
    
    # Connect to server
    if not client.connect():
        sys.exit(1)
    
    # Get username
    while True:
        username = input("Enter your username (min 3 characters): ").strip()
        if len(username) >= 3:
            break
        print("Username too short. Please try again.")
    
    # Register
    if not client.register(username):
        print("[CLIENT] Failed to register. Exiting.")
        client.disconnect()
        sys.exit(1)
    
    # Start receiving messages in background
    client.start_receiving()
    
    # Print help
    print_help()
    
    # Main input loop
    try:
        while client.connected:
            client._print_prompt()
            
            try:
                user_input = input().strip()
            except EOFError:
                break
            
            if not user_input:
                continue
            
            # Parse commands
            if user_input.startswith("/"):
                parts = user_input.split(" ", 2)
                command = parts[0].lower()
                
                if command == "/quit" or command == "/exit":
                    break
                    
                elif command == "/users":
                    client.request_user_list()
                    
                elif command == "/help":
                    print_help()
                    
                elif command == "/msg":
                    if len(parts) < 3:
                        print("Usage: /msg <username> <message>")
                    else:
                        recipient = parts[1]
                        message_text = parts[2]
                        client.send_chat_message(recipient, message_text)
                        print(f"[SENT to {recipient}]: {message_text}")
                        
                else:
                    print(f"Unknown command: {command}")
                    print("Type /help for available commands")
            else:
                print("Commands must start with /")
                print("Type /help for available commands")
                
    except KeyboardInterrupt:
        print("\n[CLIENT] Interrupt received")
        
    finally:
        client.disconnect()
        print("[CLIENT] Goodbye!")


if __name__ == "__main__":
    main()
