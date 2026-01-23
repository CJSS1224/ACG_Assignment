/**
 * Chat Module - Member 2
 * 
 * Handles chat-related functionality:
 * - Chat list management
 * - Message rendering
 * - Encryption/decryption of messages
 * - Online status tracking
 */

const Chat = {
    // Current active chat
    currentChat: null,
    
    // Chats list: Map<userId, chatInfo>
    chats: new Map(),
    
    // Online users: Map<userId, userInfo>
    onlineUsers: new Map(),
    
    // Public keys cache: Map<userId, publicKeyPem>
    publicKeys: new Map(),

    /**
     * Reset chat state (used on logout)
     */
    reset() {
        this.currentChat = null;
        this.chats.clear();
        this.onlineUsers.clear();
        this.publicKeys.clear();
    },

    /**
     * Load user's chats from server
     */
    async loadChats() {
        const chats = await ApiService.getChats();
        this.chats.clear();
        
        chats.forEach(chat => {
            this.chats.set(chat.other_user_id, {
                chatId: chat.chat_id,
                userId: chat.other_user_id,
                username: chat.other_username,
                publicKey: chat.other_public_key,
                lastMessageAt: chat.last_message_at
            });
            
            // Cache public key
            if (chat.other_public_key) {
                this.publicKeys.set(chat.other_user_id, chat.other_public_key);
            }
        });

        this.renderChatList();
    },

    /**
     * Render chat list in sidebar
     */
    renderChatList() {
        const chatList = document.getElementById('chat-list');
        
        if (this.chats.size === 0) {
            chatList.innerHTML = `
                <div class="empty-chats">
                    <i class="fas fa-comments"></i>
                    <p>No chats yet</p>
                    <button id="start-chat-btn" class="btn btn-secondary">
                        <i class="fas fa-plus"></i> Start a Chat
                    </button>
                </div>
            `;
            document.getElementById('start-chat-btn').addEventListener('click', () => {
                App.openNewChatModal();
            });
            return;
        }

        let html = '';
        this.chats.forEach((chat, userId) => {
            const isOnline = this.onlineUsers.has(userId);
            const isActive = this.currentChat && this.currentChat.userId === userId;
            
            html += `
                <div class="chat-item ${isActive ? 'active' : ''}" data-user-id="${userId}">
                    <div class="avatar">
                        <i class="fas fa-user"></i>
                        ${isOnline ? '<span class="online-indicator"></span>' : ''}
                    </div>
                    <div class="chat-item-info">
                        <div class="name">${UI.escapeHtml(chat.username)}</div>
                        <div class="last-message">${isOnline ? 'Online' : 'Offline'}</div>
                    </div>
                </div>
            `;
        });

        chatList.innerHTML = html;

        // Add click listeners
        chatList.querySelectorAll('.chat-item').forEach(item => {
            item.addEventListener('click', () => {
                const userId = parseInt(item.dataset.userId);
                this.openChat(userId);
            });
        });
    },

    /**
     * Update online status display
     */
    updateOnlineStatus() {
        this.renderChatList();
        
        // Update current chat status if open
        if (this.currentChat) {
            const isOnline = this.onlineUsers.has(this.currentChat.userId);
            const statusEl = document.getElementById('chat-status');
            statusEl.textContent = isOnline ? 'Online' : 'Offline';
            statusEl.classList.toggle('online', isOnline);
        }
    },

    /**
     * Open a chat with a user
     * @param {number} userId 
     */
    async openChat(userId) {
        const chat = this.chats.get(userId);
        if (!chat) return;

        this.currentChat = chat;

        // Update UI
        UI.hide('no-chat-selected');
        UI.show('active-chat');
        document.getElementById('chat-username').textContent = chat.username;
        
        const isOnline = this.onlineUsers.has(userId);
        const statusEl = document.getElementById('chat-status');
        statusEl.textContent = isOnline ? 'Online' : 'Offline';
        statusEl.classList.toggle('online', isOnline);

        // Update active state in chat list
        document.querySelectorAll('.chat-item').forEach(item => {
            item.classList.toggle('active', parseInt(item.dataset.userId) === userId);
        });

        // Load messages
        await this.loadMessages(userId);

        // Focus input
        document.getElementById('message-input').focus();
    },

    /**
     * Load messages for a chat
     * @param {number} userId 
     */
    async loadMessages(userId) {
        const container = document.getElementById('messages-container');
        container.innerHTML = '<div class="loading" style="text-align: center; padding: 20px;"><i class="fas fa-spinner fa-spin"></i> Loading messages...</div>';

        const messages = await ApiService.getChatMessages(userId);
        container.innerHTML = '';

        for (const msg of messages) {
            await this.renderMessage(msg, msg.sender_id === Auth.user.id);
        }

        UI.scrollToBottom(container);
    },

    /**
     * Render a single message
     * @param {Object} msgData - Message data from server
     * @param {boolean} isSent - Whether current user sent this message
     * @param {string|null} plaintextOverride - For just-sent messages, use this instead of decrypting
     */
    async renderMessage(msgData, isSent, plaintextOverride = null) {
        const container = document.getElementById('messages-container');
        
        let plaintext = '[Encrypted message]';
        let signatureStatus = '';

        // For just-sent messages, use the plaintext override (no need to decrypt)
        if (isSent && plaintextOverride) {
            plaintext = plaintextOverride;
            signatureStatus = '<i class="fas fa-check-circle verified" title="Sent"></i>';
        } else {
            // For all other messages, try to decrypt
            try {
                let senderPublicKey = null;
                if (!isSent) {
                    senderPublicKey = this.publicKeys.get(msgData.sender_id) || msgData.sender_public_key;
                }

                const decrypted = await CryptoHelper.decryptMessage({
                    encrypted_payload: msgData.encrypted_payload,
                    encrypted_key: msgData.encrypted_key,
                    encrypted_key_sender: msgData.encrypted_key_sender,
                    iv: msgData.iv,
                    signature: msgData.signature
                }, senderPublicKey);

                plaintext = decrypted.plaintext;
                
                if (isSent) {
                    signatureStatus = '<i class="fas fa-check-circle verified" title="Sent"></i>';
                } else if (decrypted.signatureValid === true) {
                    signatureStatus = '<i class="fas fa-check-circle verified" title="Signature verified"></i>';
                } else if (decrypted.signatureValid === false) {
                    signatureStatus = '<i class="fas fa-exclamation-circle failed" title="Signature invalid"></i>';
                }
            } catch (error) {
                console.error('[CHAT] Failed to decrypt message:', error);
                plaintext = '[Unable to decrypt]';
                signatureStatus = '<i class="fas fa-exclamation-triangle failed" title="Decryption failed"></i>';
            }
        }

        const time = UI.formatTime(msgData.timestamp);

        const messageEl = document.createElement('div');
        messageEl.className = `message ${isSent ? 'sent' : 'received'}`;
        messageEl.innerHTML = `
            <div class="message-content">${UI.escapeHtml(plaintext)}</div>
            <div class="message-meta">
                <span class="time">${time}</span>
                ${signatureStatus}
            </div>
        `;

        container.appendChild(messageEl);
    },

    /**
     * Handle incoming message from WebSocket
     * @param {Object} data - Message data
     */
    async handleIncomingMessage(data) {
        // Add timestamp if not present
        if (!data.timestamp) {
            data.timestamp = new Date().toISOString();
        }
        
        // Add to chats if not exists
        if (!this.chats.has(data.sender_id)) {
            this.chats.set(data.sender_id, {
                userId: data.sender_id,
                username: data.sender_username
            });
            this.renderChatList();
        }

        // Cache sender's public key
        if (data.sender_public_key && !this.publicKeys.has(data.sender_id)) {
            this.publicKeys.set(data.sender_id, data.sender_public_key);
        }

        // If chat is open, render message
        if (this.currentChat && this.currentChat.userId === data.sender_id) {
            await this.renderMessage(data, false);
            UI.scrollToBottom('messages-container');
            UI.hide('typing-indicator');
        } else {
            UI.showToast(`New message from ${data.sender_username}`, 'success');
        }
    },

    /**
     * Send a message to current chat
     * @param {string} text - Message text
     * @returns {Promise<boolean>} Success status
     */
    async sendMessage(text) {
        if (!text || !this.currentChat) return false;

        // Get recipient's public key
        let recipientPublicKey = this.publicKeys.get(this.currentChat.userId);
        
        if (!recipientPublicKey) {
            const keyData = await ApiService.getUserPublicKey(this.currentChat.userId);
            if (keyData) {
                recipientPublicKey = keyData.public_key;
                this.publicKeys.set(this.currentChat.userId, recipientPublicKey);
            }
        }

        if (!recipientPublicKey) {
            UI.showToast('Cannot send message - recipient public key not available', 'error');
            return false;
        }

        try {
            // Encrypt message
            const encrypted = await CryptoHelper.encryptMessage(text, recipientPublicKey);

            // Send via WebSocket
            Socket.sendMessage({
                recipient_id: this.currentChat.userId,
                encrypted_payload: encrypted.encrypted_payload,
                encrypted_key: encrypted.encrypted_key,
                encrypted_key_sender: encrypted.encrypted_key_sender,
                iv: encrypted.iv,
                signature: encrypted.signature,
                hmac: encrypted.hmac
            });

            // Render sent message locally with original plaintext
            const msgData = {
                timestamp: new Date().toISOString(),
                sender_id: Auth.user.id
            };
            
            await this.renderMessage(msgData, true, text);
            UI.scrollToBottom('messages-container');

            return true;
        } catch (error) {
            console.error('[CHAT] Failed to send message:', error);
            UI.showToast('Failed to send message', 'error');
            return false;
        }
    },

    /**
     * Start a new chat with a user
     * @param {number} userId 
     * @param {string} username 
     * @param {string} publicKey 
     * @returns {Promise<boolean>}
     */
    async startNewChat(userId, username, publicKey) {
        const result = await ApiService.createChat(userId);

        if (result.ok) {
            this.chats.set(userId, {
                chatId: result.data.chat_id,
                userId: userId,
                username: username,
                publicKey: publicKey || result.data.other_user.public_key
            });

            if (publicKey || result.data.other_user.public_key) {
                this.publicKeys.set(userId, publicKey || result.data.other_user.public_key);
            }

            this.renderChatList();
            this.openChat(userId);
            return true;
        }
        
        return false;
    },

    // Online user management
    addOnlineUser(userId, userInfo) {
        this.onlineUsers.set(userId, userInfo);
        this.updateOnlineStatus();
    },

    removeOnlineUser(userId) {
        this.onlineUsers.delete(userId);
        this.updateOnlineStatus();
    },

    setOnlineUsers(users) {
        this.onlineUsers.clear();
        users.forEach(user => {
            this.onlineUsers.set(user.id, user);
        });
        this.updateOnlineStatus();
    }
};

// Export for use in other modules
window.Chat = Chat;
