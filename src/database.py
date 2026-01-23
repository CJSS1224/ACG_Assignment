"""
Database Module

Handles MySQL database connections and provides a connection pool
for efficient database operations.
"""

import os
import mysql.connector
from mysql.connector import pooling
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', ''),
    'database': os.getenv('DB_DATABASE', 'secure_messaging'),
    'autocommit': True,
    'charset': 'utf8mb4'
}

# Connection pool
connection_pool = None


def init_db():
    """Initialize the database connection pool."""
    global connection_pool
    try:
        connection_pool = pooling.MySQLConnectionPool(
            pool_name="secure_messaging_pool",
            pool_size=10,
            **DB_CONFIG
        )
        print("[DATABASE] Connection pool initialized")
        return True
    except mysql.connector.Error as err:
        print(f"[DATABASE] Error initializing pool: {err}")
        return False


def get_connection():
    """Get a connection from the pool."""
    global connection_pool
    if connection_pool is None:
        init_db()
    return connection_pool.get_connection()


def execute_query(query, params=None, fetch_one=False, fetch_all=False):
    """
    Execute a SQL query and return results.
    
    Args:
        query: SQL query string
        params: Query parameters (tuple or dict)
        fetch_one: Return single row
        fetch_all: Return all rows
        
    Returns:
        Query results or lastrowid for INSERT
    """
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, params)
        
        if fetch_one:
            result = cursor.fetchone()
        elif fetch_all:
            result = cursor.fetchall()
        else:
            result = cursor.lastrowid
            
        return result
        
    except mysql.connector.Error as err:
        print(f"[DATABASE] Query error: {err}")
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def execute_procedure(proc_name, params, out_params=None):
    """
    Execute a stored procedure.
    
    Args:
        proc_name: Name of the stored procedure
        params: Input parameters
        out_params: Number of output parameters
        
    Returns:
        Output parameters or None
    """
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        result = cursor.callproc(proc_name, params)
        
        if out_params:
            # Fetch output parameters
            cursor.execute(f"SELECT {', '.join(['@_' + proc_name + '_' + str(i) for i in range(len(params))])}")
            return cursor.fetchone()
        
        return result
        
    except mysql.connector.Error as err:
        print(f"[DATABASE] Procedure error: {err}")
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
