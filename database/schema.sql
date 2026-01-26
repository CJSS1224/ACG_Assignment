-- ST2504 Applied Cryptography - SecureChat Database Schema
-- Run this script to set up the MySQL database

-- Create database
CREATE DATABASE IF NOT EXISTS secure_messaging;
USE secure_messaging;

-- Users table
-- Stores registered users with their credentials and RSA public keys
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,       -- bcrypt hashed password (Member 1)
    public_key TEXT,                            -- RSA public key in PEM format (Member 6)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    INDEX idx_username (username)
);

-- Messages table
-- Stores encrypted messages with all cryptographic components
CREATE TABLE IF NOT EXISTS messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    recipient_id INT NOT NULL,
    encrypted_payload TEXT NOT NULL,            -- AES-256-CTR encrypted message (Member 3)
    encrypted_key TEXT NOT NULL,                -- RSA-OAEP encrypted AES key for recipient (Member 6)
    encrypted_key_sender TEXT,                  -- RSA-OAEP encrypted AES key for sender (Member 6)
    iv VARCHAR(64) NOT NULL,                    -- Nonce for AES-CTR (Base64) (Member 3)
    signature TEXT NOT NULL,                    -- RSA digital signature (Member 5)
    hmac VARCHAR(64) NOT NULL,                  -- HMAC-SHA256 for integrity (Member 4)
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_read BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_sender (sender_id),
    INDEX idx_recipient (recipient_id),
    INDEX idx_timestamp (timestamp)
);

-- Chats table
-- Tracks active chat sessions between users
CREATE TABLE IF NOT EXISTS chats (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user1_id INT NOT NULL,
    user2_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_message_at TIMESTAMP NULL,
    FOREIGN KEY (user1_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (user2_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_chat (user1_id, user2_id),
    INDEX idx_user1 (user1_id),
    INDEX idx_user2 (user2_id)
);
