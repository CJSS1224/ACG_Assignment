"""
Minimal server skeleton (safe, non-production).
Run: python -m src.server.server
"""
import socket
import threading
from src.utils.constants import SERVER_HOST, SERVER_PORT, BUFFER_SIZE

def handle_client(conn, addr):
    try:
        data = conn.recv(BUFFER_SIZE)
        # ...existing code...
        conn.sendall(b"ACK")
    finally:
        conn.close()

def run_server(host=SERVER_HOST, port=SERVER_PORT):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(5)
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        srv.close()

if __name__ == "__main__":
    run_server()