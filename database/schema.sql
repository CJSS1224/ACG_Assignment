-- SecureChat Database Schema
-- ST2504 Applied Cryptography Assignment 2
-- Implemented by: Akash (User Authentication & Database Specialist)
-- ==========================================

-- Create database
CREATE DATABASE IF NOT EXISTS securechat;
USE securechat;

-- =============================================================================
-- USERS TABLE
-- =============================================================================
-- Stores user credentials and RSA keys
-- 
-- Security notes:
--   - password_hash: bcrypt hashed (never store plaintext!)
--   - public_key: Stored in plaintext (it's public)
--   - encrypted_private_key: AES-GCM encrypted with password-derived key
--   - private_key_nonce, tag, salt: Required to decrypt private key

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    
    -- RSA Public Key (shareable)
    public_key TEXT NOT NULL,
    
    -- RSA Private Key (encrypted with AES-GCM)
    encrypted_private_key TEXT NOT NULL,
    private_key_nonce VARCHAR(32) NOT NULL,     -- Base64: 12 bytes -> ~16 chars
    private_key_tag VARCHAR(32) NOT NULL,       -- Base64: 16 bytes -> ~24 chars
    private_key_salt VARCHAR(32) NOT NULL,      -- Base64: 16 bytes -> ~24 chars
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_username (username)
);

-- =============================================================================
-- MESSAGES TABLE
-- =============================================================================
-- Stores encrypted messages with all cryptographic components
--
-- CONFIDENTIALITY AT REST:
--   - ciphertext: AES-256-GCM encrypted message
--   - nonce: Unique per message (prevents replay)
--   - tag: GCM authentication tag (integrity)
--
-- KEY EXCHANGE:
--   - encrypted_key: AES key encrypted for recipient (RSA-OAEP)
--   - encrypted_key_sender: AES key encrypted for sender (so they can read own messages)
--
-- NON-REPUDIATION AT REST:
--   - signature: RSA-PSS signature over (ciphertext || nonce)

CREATE TABLE IF NOT EXISTS messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    recipient_id INT NOT NULL,
    
    -- Encrypted message (AES-256-GCM)
    ciphertext TEXT NOT NULL,
    nonce VARCHAR(32) NOT NULL,
    tag VARCHAR(32) NOT NULL,
    
    -- Encrypted AES keys (RSA-OAEP)
    encrypted_key TEXT NOT NULL,            -- For recipient
    encrypted_key_sender TEXT NOT NULL,     -- For sender
    
    -- Digital signature (RSA-PSS)
    signature TEXT NOT NULL,
    
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_read BOOLEAN DEFAULT FALSE,
    
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE,
    
    INDEX idx_sender (sender_id),
    INDEX idx_recipient (recipient_id),
    INDEX idx_conversation (sender_id, recipient_id),
    INDEX idx_timestamp (timestamp)
);

-- =============================================================================
-- CHATS TABLE
-- =============================================================================
-- Tracks active conversations between users

CREATE TABLE IF NOT EXISTS chats (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user1_id INT NOT NULL,
    user2_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_message_at TIMESTAMP NULL,
    
    FOREIGN KEY (user1_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (user2_id) REFERENCES users(id) ON DELETE CASCADE,
    
    -- Ensure only one chat record per user pair
    UNIQUE KEY unique_chat (user1_id, user2_id),
    
    INDEX idx_user1 (user1_id),
    INDEX idx_user2 (user2_id)
);

-- =============================================================================
-- SESSIONS TABLE
-- =============================================================================
-- Stores session secrets for HMAC transit integrity
-- Alternative: Store in memory/Redis for better performance

CREATE TABLE IF NOT EXISTS sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    session_secret VARCHAR(64) NOT NULL,    -- Base64: 32 bytes -> ~44 chars
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    
    INDEX idx_user (user_id),
    INDEX idx_expires (expires_at)
);
