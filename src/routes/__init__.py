"""
Routes Package

Contains all Flask route blueprints.
"""

from src.routes.auth_routes import auth_bp
from src.routes.user_routes import user_bp
from src.routes.chat_routes import chat_bp

__all__ = ['auth_bp', 'user_bp', 'chat_bp']
