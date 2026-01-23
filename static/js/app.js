/**
 * SecureChat Application - Main Entry Point
 * 
 * This module coordinates all other modules and handles:
 * - Application initialization
 * - Event listener setup
 * - UI flow management
 * 
 * Module Dependencies:
 * - CryptoHelper (crypto/index.js)
 * - Auth (auth.js)
 * - Chat (chat.js)
 * - Socket (socket.js)
 * - ApiService (api.js)
 * - UI (ui.js)
 */

const App = {
    /**
     * Initialize the application
     */
    async init() {
        console.log('[APP] Initializing SecureChat...');
        
        // Initialize crypto module
        await CryptoHelper.init();
        
        // Check for existing session
        const hasSession = await Auth.init();
        
        if (hasSession) {
            this.showChatInterface();
            this.connectWebSocket();
        }
        
        // Set up event listeners
        this.setupEventListeners();
    },

    /**
     * Set up all DOM event listeners
     */
    setupEventListeners() {
        // Auth form switching
        document.getElementById('show-register').addEventListener('click', (e) => {
            e.preventDefault();
            document.getElementById('login-form').classList.remove('active');
            document.getElementById('register-form').classList.add('active');
        });

        document.getElementById('show-login').addEventListener('click', (e) => {
            e.preventDefault();
            document.getElementById('register-form').classList.remove('active');
            document.getElementById('login-form').classList.add('active');
        });

        // Login form submission
        document.getElementById('login-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleLogin();
        });

        // Register form submission
        document.getElementById('register-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleRegister();
        });

        // Logout button
        document.getElementById('logout-btn').addEventListener('click', () => {
            this.logout();
        });

        // New chat button
        document.getElementById('new-chat-btn').addEventListener('click', () => {
            this.openNewChatModal();
        });

        // Close modal buttons
        document.getElementById('close-modal').addEventListener('click', () => {
            this.closeNewChatModal();
        });
        document.getElementById('close-info-modal').addEventListener('click', () => {
            UI.hide('chat-info-modal');
        });

        // Chat info button
        document.getElementById('chat-info-btn').addEventListener('click', () => {
            this.showChatInfo();
        });

        // Copy public key button
        document.getElementById('copy-key-btn').addEventListener('click', () => {
            const textarea = document.getElementById('my-public-key');
            textarea.select();
            document.execCommand('copy');
            UI.showToast('Public key copied!', 'success');
        });

        // Message input (Enter to send)
        const messageInput = document.getElementById('message-input');
        messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });

        // Typing indicator
        let typingTimeout;
        messageInput.addEventListener('input', () => {
            if (Chat.currentChat) {
                Socket.emitTyping(Chat.currentChat.userId);
                
                clearTimeout(typingTimeout);
                typingTimeout = setTimeout(() => {
                    Socket.emitStopTyping(Chat.currentChat.userId);
                }, 1000);
            }
        });

        // Send button
        document.getElementById('send-btn').addEventListener('click', () => {
            this.sendMessage();
        });

        // Click outside modal to close
        document.getElementById('new-chat-modal').addEventListener('click', (e) => {
            if (e.target.id === 'new-chat-modal') {
                this.closeNewChatModal();
            }
        });
        document.getElementById('chat-info-modal').addEventListener('click', (e) => {
            if (e.target.id === 'chat-info-modal') {
                UI.hide('chat-info-modal');
            }
        });
    },

    /**
     * Handle login form submission
     */
    async handleLogin() {
        const username = document.getElementById('login-username').value.trim();
        const password = document.getElementById('login-password').value;

        if (!username || !password) {
            UI.showToast('Please enter username and password', 'error');
            return;
        }

        const result = await Auth.login(username, password);

        if (!result.success) {
            UI.showToast(result.error, 'error');
            return;
        }

        UI.showToast('Login successful!', 'success');
        this.showChatInterface();
        this.connectWebSocket();
    },

    /**
     * Handle registration form submission
     */
    async handleRegister() {
        const username = document.getElementById('register-username').value.trim();
        const password = document.getElementById('register-password').value;
        const confirm = document.getElementById('register-confirm').value;

        if (!username || username.length < 3) {
            UI.showToast('Username must be at least 3 characters', 'error');
            return;
        }

        if (!password || password.length < 6) {
            UI.showToast('Password must be at least 6 characters', 'error');
            return;
        }

        if (password !== confirm) {
            UI.showToast('Passwords do not match', 'error');
            return;
        }

        const result = await Auth.register(username, password);

        if (!result.success) {
            UI.showToast(result.error, 'error');
            return;
        }

        UI.showToast('Registration successful!', 'success');
        this.showChatInterface();
        this.connectWebSocket();
    },

    /**
     * Handle logout
     */
    logout() {
        Socket.disconnect();
        Auth.logout();
        Chat.reset();

        // Show auth interface
        UI.show('auth-container');
        UI.hide('chat-container');

        // Reset forms
        document.getElementById('login-form').reset();
        document.getElementById('register-form').reset();
        document.getElementById('login-form').classList.add('active');
        document.getElementById('register-form').classList.remove('active');

        UI.showToast('Logged out successfully', 'success');
    },

    /**
     * Show chat interface after successful login
     */
    showChatInterface() {
        UI.hide('auth-container');
        UI.show('chat-container');
        document.getElementById('current-username').textContent = Auth.user.username;
        
        // Load existing chats
        Chat.loadChats();
    },

    /**
     * Connect to WebSocket server
     */
    connectWebSocket() {
        Socket.connect(Auth.token);
    },

    /**
     * Open new chat modal
     */
    async openNewChatModal() {
        const modal = document.getElementById('new-chat-modal');
        const usersList = document.getElementById('online-users-list');
        
        UI.show(modal);
        usersList.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> Loading users...</div>';

        // Request online users
        Socket.requestOnlineUsers();
        
        // Fetch from API
        const users = await ApiService.getOnlineUsers();
        
        if (users.length === 0) {
            usersList.innerHTML = `
                <div class="no-users-message">
                    <i class="fas fa-user-slash"></i>
                    <p>No other users online</p>
                </div>
            `;
            return;
        }

        let html = '';
        users.forEach(user => {
            html += `
                <div class="online-user-item" data-user-id="${user.id}" data-username="${UI.escapeHtml(user.username)}" data-public-key="${UI.escapeHtml(user.public_key || '')}">
                    <div class="avatar">
                        <i class="fas fa-user"></i>
                        <span class="online-indicator"></span>
                    </div>
                    <span class="username">${UI.escapeHtml(user.username)}</span>
                    <span class="status"><i class="fas fa-circle"></i> Online</span>
                </div>
            `;
        });

        usersList.innerHTML = html;

        // Add click listeners
        usersList.querySelectorAll('.online-user-item').forEach(item => {
            item.addEventListener('click', () => {
                const userId = parseInt(item.dataset.userId);
                const username = item.dataset.username;
                const publicKey = item.dataset.publicKey;
                this.startNewChat(userId, username, publicKey);
            });
        });
    },

    /**
     * Close new chat modal
     */
    closeNewChatModal() {
        UI.hide('new-chat-modal');
    },

    /**
     * Start a new chat
     */
    async startNewChat(userId, username, publicKey) {
        this.closeNewChatModal();
        
        const success = await Chat.startNewChat(userId, username, publicKey);
        
        if (!success) {
            UI.showToast('Failed to start chat', 'error');
        }
    },

    /**
     * Send a message
     */
    async sendMessage() {
        const input = document.getElementById('message-input');
        const text = input.value.trim();

        if (!text) return;

        const success = await Chat.sendMessage(text);
        
        if (success) {
            input.value = '';
        }
    },

    /**
     * Show chat info modal
     */
    showChatInfo() {
        document.getElementById('my-public-key').value = CryptoHelper.getPublicKey() || 'Not available';
        UI.show('chat-info-modal');
    }
};

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    App.init();
});
