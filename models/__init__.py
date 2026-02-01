"""
Models Package
==============
Database and service layer for SecureChat.

Modules:
    - database: Low-level database operations [Akash]
    - user: User authentication and key management [Akash]
    - message: Encrypted message operations [Solomon]
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.database import Database
from models.user import UserService
from models.message import MessageService

__all__ = ['Database', 'UserService', 'MessageService']
