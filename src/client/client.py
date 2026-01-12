"""
Minimal client skeleton.
Run: python -m src.client.client
"""
import socket
from src.utils.constants import SERVER_HOST, SERVER_PORT, BUFFER_SIZE

def send_message(message: bytes):
    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as s:
        s.sendall(message)
        return s.recv(BUFFER_SIZE)

if __name__ == "__main__":
    resp = send_message(b"hello")
    print("Server response:", resp)
