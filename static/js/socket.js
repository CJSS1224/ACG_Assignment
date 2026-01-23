/**
 * WebSocket Module - Member 1
 * 
 * Handles WebSocket connection and real-time events:
 * - Connection management
 * - Online user tracking
 * - Message events
 * - Typing indicators
 */

const Socket = {
    socket: null,

    /**
     * Connect to WebSocket server
     * @param {string} token - JWT authentication token
     * @returns {SocketIO} Socket instance
     */
    connect(token) {
        if (this.socket) {
            this.socket.disconnect();
        }

        UI.updateConnectionStatus('connecting');

        // Connect with token in query params
        this.socket = io({
            query: { token: token }
        });

        this.setupEventHandlers();
        
        return this.socket;
    },

    /**
     * Disconnect from WebSocket server
     */
    disconnect() {
        if (this.socket) {
            this.socket.disconnect();
            this.socket = null;
        }
    },

    /**
     * Get socket instance
     * @returns {SocketIO|null}
     */
    getSocket() {
        return this.socket;
    },

    /**
     * Setup WebSocket event handlers
     */
    setupEventHandlers() {
        // Connection events
        this.socket.on('connect', () => {
            console.log('[SOCKET] Connected');
            UI.updateConnectionStatus('connected');
            this.socket.emit('get_online_users');
        });

        this.socket.on('disconnect', () => {
            console.log('[SOCKET] Disconnected');
            UI.updateConnectionStatus('disconnected');
        });

        this.socket.on('connect_error', (error) => {
            console.error('[SOCKET] Connection error:', error);
            UI.updateConnectionStatus('disconnected');
        });

        // User status events
        this.socket.on('user_online', (data) => {
            console.log('[SOCKET] User online:', data.username);
            Chat.addOnlineUser(data.user_id, data);
        });

        this.socket.on('user_offline', (data) => {
            console.log('[SOCKET] User offline:', data.username);
            Chat.removeOnlineUser(data.user_id);
        });

        this.socket.on('online_users_list', (data) => {
            console.log('[SOCKET] Online users:', data.users.length);
            Chat.setOnlineUsers(data.users);
        });

        // Message events
        this.socket.on('new_message', async (data) => {
            console.log('[SOCKET] New message from:', data.sender_username);
            await Chat.handleIncomingMessage(data);
        });

        this.socket.on('message_sent', (data) => {
            console.log('[SOCKET] Message sent:', data.message_id);
        });

        // Typing events
        this.socket.on('user_typing', (data) => {
            if (Chat.currentChat && Chat.currentChat.userId === data.user_id) {
                UI.show('typing-indicator');
            }
        });

        this.socket.on('user_stop_typing', (data) => {
            if (Chat.currentChat && Chat.currentChat.userId === data.user_id) {
                UI.hide('typing-indicator');
            }
        });

        // Error events
        this.socket.on('error', (data) => {
            console.error('[SOCKET] Error:', data.message);
            UI.showToast(data.message, 'error');
        });
    },

    /**
     * Emit typing indicator
     * @param {number} recipientId 
     */
    emitTyping(recipientId) {
        if (this.socket) {
            this.socket.emit('typing', { recipient_id: recipientId });
        }
    },

    /**
     * Emit stop typing indicator
     * @param {number} recipientId 
     */
    emitStopTyping(recipientId) {
        if (this.socket) {
            this.socket.emit('stop_typing', { recipient_id: recipientId });
        }
    },

    /**
     * Request online users list from server
     */
    requestOnlineUsers() {
        if (this.socket) {
            this.socket.emit('get_online_users');
        }
    },

    /**
     * Send an encrypted message via WebSocket
     * @param {Object} messageData - Encrypted message data
     */
    sendMessage(messageData) {
        if (this.socket) {
            this.socket.emit('send_message', messageData);
        }
    }
};

// Export for use in other modules
window.Socket = Socket;
