-- ST2504 Applied Cryptography - Secure Messaging Database Schema
-- Run this script to set up the MySQL database

-- Create database
DROP DATABASE IF EXISTS secure_messaging;
CREATE DATABASE IF NOT EXISTS secure_messaging;
USE secure_messaging;

-- Users table
-- Stores registered users with their credentials and RSA public keys
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    public_key TEXT,                          -- RSA public key in PEM format
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    INDEX idx_username (username)
);

-- Messages table
-- Stores encrypted messages with signatures for non-repudiation
CREATE TABLE IF NOT EXISTS messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    recipient_id INT NOT NULL,
    encrypted_payload TEXT NOT NULL,          -- AES encrypted message content
    encrypted_key TEXT NOT NULL,              -- RSA encrypted AES key (for recipient)
    encrypted_key_sender TEXT,                -- RSA encrypted AES key (for sender to read own messages)
    iv VARCHAR(64) NOT NULL,                  -- Initialization vector (Base64)
    signature TEXT NOT NULL,                  -- RSA digital signature
    hmac VARCHAR(64) NOT NULL,                -- HMAC for integrity
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

-- Online status table (for tracking connected users)
CREATE TABLE IF NOT EXISTS user_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    session_id VARCHAR(255) NOT NULL,
    connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_session (session_id),
    INDEX idx_user (user_id)
);

-- View to get online users (active in last 5 minutes)
CREATE OR REPLACE VIEW online_users AS
SELECT DISTINCT u.id, u.username, u.public_key
FROM users u
INNER JOIN user_sessions us ON u.id = us.user_id
WHERE us.last_activity > DATE_SUB(NOW(), INTERVAL 5 MINUTE);

DELIMITER //

-- Stored procedure to get or create a chat between two users
CREATE PROCEDURE IF NOT EXISTS get_or_create_chat(
    IN p_user1_id INT,
    IN p_user2_id INT,
    OUT p_chat_id INT
)
BEGIN
    DECLARE existing_chat_id INT DEFAULT NULL;
    
    -- Ensure user1_id < user2_id for consistency
    IF p_user1_id > p_user2_id THEN
        SET @temp = p_user1_id;
        SET p_user1_id = p_user2_id;
        SET p_user2_id = @temp;
    END IF;
    
    -- Check if chat exists
    SELECT id INTO existing_chat_id
    FROM chats
    WHERE (user1_id = p_user1_id AND user2_id = p_user2_id)
       OR (user1_id = p_user2_id AND user2_id = p_user1_id)
    LIMIT 1;
    
    IF existing_chat_id IS NOT NULL THEN
        SET p_chat_id = existing_chat_id;
    ELSE
        -- Create new chat
        INSERT INTO chats (user1_id, user2_id) VALUES (p_user1_id, p_user2_id);
        SET p_chat_id = LAST_INSERT_ID();
    END IF;
END //

DELIMITER ;

-- Sample data for testing (optional - comment out in production)
-- INSERT INTO users (username, password_hash) VALUES 
--     ('alice', '$2b$10$...'),  -- password: alice123
--     ('bob', '$2b$10$...');    -- password: bob123
