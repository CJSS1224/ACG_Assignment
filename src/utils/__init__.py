"""
Utilities Module

This module contains shared utilities, constants, and helper functions
used across the entire application.

Sub-modules:
    - constants.py : Configuration values (ports, paths, key sizes)
    - helpers.py   : Common utility functions (encoding, timestamps)
    - protocol.py  : Message protocol definitions and serialization

These utilities ensure consistency across the server and client applications
and reduce code duplication.
"""

# LEARN: Centralizing constants and helpers in one place means if you need
# LEARN: to change something (like the server port), you only change it in
# LEARN: one file instead of hunting through all your code.

from src.utils.constants import *
from src.utils.helpers import *
from src.utils.protocol import MessageType, Message
