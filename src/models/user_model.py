"""
User Model

Handles all database operations related to users including
registration, authentication, and public key management.
"""

from src.database import execute_query


def create_user(username, password_hash, public_key=None):
    """
    Create a new user in the database.
    
    Args:
        username: Unique username
        password_hash: Bcrypt hashed password
        public_key: RSA public key in PEM format (optional)
        
    Returns:
        New user ID or None if failed
    """
    query = """
        INSERT INTO users (username, password_hash, public_key)
        VALUES (%s, %s, %s)
    """
    try:
        user_id = execute_query(query, (username, password_hash, public_key))
        return user_id
    except Exception as e:
        if 'Duplicate entry' in str(e):
            return None  # Username already exists
        raise


def get_user_by_username(username):
    """
    Get user by username.
    
    Args:
        username: Username to search for
        
    Returns:
        User dict or None if not found
    """
    query = """
        SELECT id, username, password_hash, public_key, created_at, last_login
        FROM users
        WHERE username = %s
    """
    return execute_query(query, (username,), fetch_one=True)


def get_user_by_id(user_id):
    """
    Get user by ID.
    
    Args:
        user_id: User ID to search for
        
    Returns:
        User dict or None if not found
    """
    query = """
        SELECT id, username, public_key, created_at, last_login
        FROM users
        WHERE id = %s
    """
    return execute_query(query, (user_id,), fetch_one=True)


def update_public_key(user_id, public_key):
    """
    Update user's RSA public key.
    
    Args:
        user_id: User ID
        public_key: New public key in PEM format
        
    Returns:
        True if successful
    """
    query = """
        UPDATE users
        SET public_key = %s
        WHERE id = %s
    """
    execute_query(query, (public_key, user_id))
    return True


def update_last_login(user_id):
    """
    Update user's last login timestamp.
    
    Args:
        user_id: User ID
    """
    query = """
        UPDATE users
        SET last_login = CURRENT_TIMESTAMP
        WHERE id = %s
    """
    execute_query(query, (user_id,))


def get_all_users(exclude_user_id=None):
    """
    Get all users, optionally excluding one user.
    
    Args:
        exclude_user_id: User ID to exclude from results
        
    Returns:
        List of user dicts
    """
    if exclude_user_id:
        query = """
            SELECT id, username, public_key
            FROM users
            WHERE id != %s
            ORDER BY username
        """
        return execute_query(query, (exclude_user_id,), fetch_all=True)
    else:
        query = """
            SELECT id, username, public_key
            FROM users
            ORDER BY username
        """
        return execute_query(query, fetch_all=True)


# Session management for online status
def create_session(user_id, session_id):
    """
    Create a user session (mark user as online).
    
    Args:
        user_id: User ID
        session_id: Socket session ID
    """
    # First remove any existing sessions for this user
    delete_query = "DELETE FROM user_sessions WHERE user_id = %s"
    execute_query(delete_query, (user_id,))
    
    # Create new session
    query = """
        INSERT INTO user_sessions (user_id, session_id)
        VALUES (%s, %s)
    """
    execute_query(query, (user_id, session_id))


def delete_session(session_id):
    """
    Delete a user session (mark user as offline).
    
    Args:
        session_id: Socket session ID
    """
    query = "DELETE FROM user_sessions WHERE session_id = %s"
    execute_query(query, (session_id,))


def delete_user_sessions(user_id):
    """
    Delete all sessions for a user.
    
    Args:
        user_id: User ID
    """
    query = "DELETE FROM user_sessions WHERE user_id = %s"
    execute_query(query, (user_id,))


def update_session_activity(session_id):
    """
    Update last activity timestamp for a session.
    
    Args:
        session_id: Socket session ID
    """
    query = """
        UPDATE user_sessions
        SET last_activity = CURRENT_TIMESTAMP
        WHERE session_id = %s
    """
    execute_query(query, (session_id,))


def get_online_users(exclude_user_id=None):
    """
    Get list of currently online users.
    
    Args:
        exclude_user_id: User ID to exclude
        
    Returns:
        List of online user dicts
    """
    if exclude_user_id:
        query = """
            SELECT DISTINCT u.id, u.username, u.public_key
            FROM users u
            INNER JOIN user_sessions us ON u.id = us.user_id
            WHERE us.last_activity > DATE_SUB(NOW(), INTERVAL 5 MINUTE)
            AND u.id != %s
            ORDER BY u.username
        """
        return execute_query(query, (exclude_user_id,), fetch_all=True)
    else:
        query = """
            SELECT DISTINCT u.id, u.username, u.public_key
            FROM users u
            INNER JOIN user_sessions us ON u.id = us.user_id
            WHERE us.last_activity > DATE_SUB(NOW(), INTERVAL 5 MINUTE)
            ORDER BY u.username
        """
        return execute_query(query, fetch_all=True)


def get_user_by_session(session_id):
    """
    Get user associated with a session.
    
    Args:
        session_id: Socket session ID
        
    Returns:
        User dict or None
    """
    query = """
        SELECT u.id, u.username, u.public_key
        FROM users u
        INNER JOIN user_sessions us ON u.id = us.user_id
        WHERE us.session_id = %s
    """
    return execute_query(query, (session_id,), fetch_one=True)
