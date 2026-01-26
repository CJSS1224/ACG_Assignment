"""
Page Routes - ST2504 Applied Cryptography

Routes for serving HTML pages.
- Charles: Client Interface
"""

from flask import Blueprint, render_template

page_bp = Blueprint('pages', __name__)


@page_bp.route('/')
def index():
    """Serve the main chat interface."""
    return render_template('index.html')
