"""
Server Module - Member 1: [Name]

This module contains the server-side application that:
- Accepts client connections via TCP sockets
- Authenticates clients using certificates
- Routes encrypted messages between clients
- Stores messages securely (encrypted at rest)

Main Components:
    - server.py : Main server application entry point
"""

# LEARN: This __init__.py makes 'server' a subpackage of 'src'
# LEARN: You can now do: from src.server import server
# LEARN: Or: from src.server.server import SecureServer
