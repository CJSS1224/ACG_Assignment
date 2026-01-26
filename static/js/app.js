/**
 * ST2504 Applied Cryptography - SecureChat Client
 * 
 * This is a MINIMAL JavaScript file for UI interactions only.
 * All cryptographic operations are handled by Python on the server.
 * 
 * Charles
 */

// =============================================================================
// APPLICATION STATE
// =============================================================================

const App = {
    user: null,
    token: null,
    socket: null,
    currentChat: null,
    privateKey: null,  // Stored locally for decryption
    chats: new Map(),
    onlineUsers: new Map(),
    publicKeys: new Map()
};

// =============================================================================
// INITIALIZATION
// =============================================================================

document.addEventListener('DOMContentLoaded', () => {
    console.log('[APP] Initializing SecureChat...');
    
    // Check for existing session
    const storedToken = localStorage.getItem('authToken');
    const storedUser = localStorage.getItem('loggedInUser');
    const storedPrivateKey = localStorage.getItem('privateKey');
    
    if (storedToken && storedUser && storedPrivateKey) {
        App.token = storedToken;
        App.user = JSON.parse(storedUser);
        App.privateKey = storedPrivateKey;
        
        // Verify token
        verifyToken().then(valid => {
            if (valid) {
                showChatInterface();
                connectWebSocket();
            } else {
                logout();
            }
        });
    }
    
    setupEventListeners();
});

// =============================================================================
// EVENT LISTENERS
// =============================================================================

function setupEventListeners() {
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

    // Login form
    document.getElementById('login-form').addEventListener('submit', (e) => {
        e.preventDefault();
        handleLogin();
    });

    // Register form
    document.getElementById('register-form').addEventListener('submit', (e) => {
        e.preventDefault();
        handleRegister();
    });

    // Logout
    document.getElementById('logout-btn').addEventListener('click', logout);

    // New chat
    document.getElementById('new-chat-btn').addEventListener('click', openNewChatModal);
    document.getElementById('close-modal').addEventListener('click', closeNewChatModal);

    // Chat info
    document.getElementById('chat-info-btn').addEventListener('click', showChatInfo);
    document.getElementById('close-info-modal').addEventListener('click', () => {
        document.getElementById('chat-info-modal').classList.add('hidden');
    });

    // Copy key
    document.getElementById('copy-key-btn').addEventListener('click', () => {
        const textarea = document.getElementById('my-public-key');
        textarea.select();
        document.execCommand('copy');
        showToast('Public key copied!', 'success');
    });

    // Message input
    const messageInput = document.getElementById('message-input');
    messageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });

    // Typing indicator
    let typingTimeout;
    messageInput.addEventListener('input', () => {
        if (App.currentChat && App.socket) {
            App.socket.emit('typing', { recipient_id: App.currentChat.userId });
            clearTimeout(typingTimeout);
            typingTimeout = setTimeout(() => {
                App.socket.emit('stop_typing', { recipient_id: App.currentChat.userId });
            }, 1000);
        }
    });

    // Send button
    document.getElementById('send-btn').addEventListener('click', sendMessage);

    // Modal backdrop clicks
    document.getElementById('new-chat-modal').addEventListener('click', (e) => {
        if (e.target.id === 'new-chat-modal') closeNewChatModal();
    });
    document.getElementById('chat-info-modal').addEventListener('click', (e) => {
        if (e.target.id === 'chat-info-modal') {
            document.getElementById('chat-info-modal').classList.add('hidden');
        }
    });
}

// =============================================================================
// AUTHENTICATION
// =============================================================================

async function handleLogin() {
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;

    if (!username || !password) {
        showToast('Please enter username and password', 'error');
        return;
    }

    // Check if we have a private key stored for this user
    const storedPrivateKey = localStorage.getItem('privateKey');
    if (!storedPrivateKey) {
        showToast('No private key found. Please register first.', 'error');
        return;
    }

    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (!response.ok) {
            showToast(data.error || 'Login failed', 'error');
            return;
        }

        // Store session
        App.token = data.token;
        App.user = data.user;
        App.privateKey = storedPrivateKey;
        
        localStorage.setItem('authToken', data.token);
        localStorage.setItem('loggedInUser', JSON.stringify(data.user));

        showToast('Login successful!', 'success');
        showChatInterface();
        connectWebSocket();

    } catch (error) {
        console.error('[APP] Login error:', error);
        showToast('An error occurred during login', 'error');
    }
}

async function handleRegister() {
    const username = document.getElementById('register-username').value.trim();
    const password = document.getElementById('register-password').value;
    const confirm = document.getElementById('register-confirm').value;

    if (!username || username.length < 3) {
        showToast('Username must be at least 3 characters', 'error');
        return;
    }

    if (!password || password.length < 6) {
        showToast('Password must be at least 6 characters', 'error');
        return;
    }

    if (password !== confirm) {
        showToast('Passwords do not match', 'error');
        return;
    }

    try {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (!response.ok) {
            showToast(data.error || 'Registration failed', 'error');
            return;
        }

        // Store session and private key
        App.token = data.token;
        App.user = {
            id: data.user_id,
            username: data.username,
            public_key: data.public_key
        };
        App.privateKey = data.private_key;

        localStorage.setItem('authToken', data.token);
        localStorage.setItem('loggedInUser', JSON.stringify(App.user));
        localStorage.setItem('privateKey', data.private_key);  // Store private key securely

        showToast('Registration successful!', 'success');
        showChatInterface();
        connectWebSocket();

    } catch (error) {
        console.error('[APP] Registration error:', error);
        showToast('An error occurred during registration', 'error');
    }
}

function logout() {
    if (App.socket) {
        App.socket.disconnect();
        App.socket = null;
    }

    App.user = null;
    App.token = null;
    App.currentChat = null;
    App.chats.clear();
    App.onlineUsers.clear();
    
    localStorage.removeItem('authToken');
    localStorage.removeItem('loggedInUser');
    // Note: Keep privateKey in localStorage for future logins

    document.getElementById('auth-container').classList.remove('hidden');
    document.getElementById('chat-container').classList.add('hidden');

    document.getElementById('login-form').reset();
    document.getElementById('register-form').reset();
    document.getElementById('login-form').classList.add('active');
    document.getElementById('register-form').classList.remove('active');

    showToast('Logged out successfully', 'success');
}

async function verifyToken() {
    try {
        const response = await fetch('/api/me', {
            headers: { 'Authorization': `Bearer ${App.token}` }
        });
        return response.ok;
    } catch {
        return false;
    }
}

// =============================================================================
// CHAT INTERFACE
// =============================================================================

function showChatInterface() {
    document.getElementById('auth-container').classList.add('hidden');
    document.getElementById('chat-container').classList.remove('hidden');
    document.getElementById('current-username').textContent = App.user.username;
    loadChats();
}

async function loadChats() {
    console.log('[APP] Loading chats...');
    try {
        const response = await fetch('/api/chats', {
            headers: { 'Authorization': `Bearer ${App.token}` }
        });

        console.log('[APP] Chats response status:', response.status);
        
        if (response.ok) {
            const chats = await response.json();
            console.log('[APP] Loaded chats:', chats);
            App.chats.clear();

            chats.forEach(chat => {
                console.log('[APP] Adding chat with user:', chat.other_user_id, chat.other_username);
                App.chats.set(chat.other_user_id, {
                    chatId: chat.chat_id,
                    userId: chat.other_user_id,
                    username: chat.other_username,
                    publicKey: chat.other_public_key,
                    lastMessageAt: chat.last_message_at
                });

                if (chat.other_public_key) {
                    App.publicKeys.set(chat.other_user_id, chat.other_public_key);
                }
            });

            console.log('[APP] Total chats loaded:', App.chats.size);
            renderChatList();
        } else {
            console.error('[APP] Failed to load chats, status:', response.status);
        }
    } catch (error) {
        console.error('[APP] Failed to load chats:', error);
    }
}

function renderChatList() {
    const chatList = document.getElementById('chat-list');

    if (App.chats.size === 0) {
        chatList.innerHTML = `
            <div class="empty-chats">
                <i class="fas fa-comments"></i>
                <p>No chats yet</p>
                <button onclick="openNewChatModal()" class="btn btn-secondary">
                    <i class="fas fa-plus"></i> Start a Chat
                </button>
            </div>
        `;
        return;
    }

    let html = '';
    App.chats.forEach((chat, userId) => {
        const isOnline = App.onlineUsers.has(userId);
        const isActive = App.currentChat && App.currentChat.userId === userId;

        html += `
            <div class="chat-item ${isActive ? 'active' : ''}" onclick="openChat(${userId})">
                <div class="avatar">
                    <i class="fas fa-user"></i>
                    ${isOnline ? '<span class="online-indicator"></span>' : ''}
                </div>
                <div class="chat-item-info">
                    <div class="name">${escapeHtml(chat.username)}</div>
                    <div class="last-message">${isOnline ? 'Online' : 'Offline'}</div>
                </div>
            </div>
        `;
    });

    chatList.innerHTML = html;
}

async function openChat(userId) {
    const chat = App.chats.get(userId);
    if (!chat) return;

    App.currentChat = chat;

    document.getElementById('no-chat-selected').classList.add('hidden');
    document.getElementById('active-chat').classList.remove('hidden');
    document.getElementById('chat-username').textContent = chat.username;

    const isOnline = App.onlineUsers.has(userId);
    const statusEl = document.getElementById('chat-status');
    statusEl.textContent = isOnline ? 'Online' : 'Offline';
    statusEl.classList.toggle('online', isOnline);

    renderChatList();
    await loadMessages(userId);
    document.getElementById('message-input').focus();
}

async function loadMessages(userId) {
    const container = document.getElementById('messages-container');
    container.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> Loading messages...</div>';

    try {
        // POST request with private key for server-side decryption
        const response = await fetch(`/api/chats/${userId}/messages`, {
            method: 'POST',
            headers: { 
                'Authorization': `Bearer ${App.token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                private_key: App.privateKey
            })
        });

        if (response.ok) {
            const messages = await response.json();
            container.innerHTML = '';

            for (const msg of messages) {
                const isSent = msg.sender_id === App.user.id;
                const text = msg.plaintext || '[Encrypted]';
                renderMessage(msg, isSent, text);
            }

            container.scrollTop = container.scrollHeight;
        }
    } catch (error) {
        console.error('[APP] Failed to load messages:', error);
        container.innerHTML = '<p style="text-align: center; color: var(--text-secondary);">Failed to load messages</p>';
    }
}

function renderMessage(msgData, isSent, plaintext = null) {
    const container = document.getElementById('messages-container');

    // If plaintext not provided, we need to decrypt on client
    // For now, show encrypted indicator (decryption will be done by Python API)
    let displayText = plaintext || '[Encrypted - loading...]';
    let signatureStatus = isSent 
        ? '<i class="fas fa-check-circle verified" title="Sent"></i>'
        : '<i class="fas fa-lock" title="Encrypted"></i>';

    const time = msgData.timestamp 
        ? new Date(msgData.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        : 'Now';

    const messageEl = document.createElement('div');
    messageEl.className = `message ${isSent ? 'sent' : 'received'}`;
    messageEl.innerHTML = `
        <div class="message-content">${escapeHtml(displayText)}</div>
        <div class="message-meta">
            <span class="time">${time}</span>
            ${signatureStatus}
        </div>
    `;

    container.appendChild(messageEl);
}

// =============================================================================
// MESSAGING
// =============================================================================

async function sendMessage() {
    const input = document.getElementById('message-input');
    const text = input.value.trim();

    if (!text || !App.currentChat) return;

    if (!App.privateKey) {
        showToast('Private key not available. Please login again.', 'error');
        return;
    }

    // Send message to server for encryption (Python handles all crypto)
    App.socket.emit('send_message', {
        recipient_id: App.currentChat.userId,
        plaintext: text,
        private_key: App.privateKey  // Server uses this for signing
    });

    input.value = '';

    // Show sent message immediately
    const msgData = {
        timestamp: new Date().toISOString(),
        sender_id: App.user.id
    };
    renderMessage(msgData, true, text);

    const container = document.getElementById('messages-container');
    container.scrollTop = container.scrollHeight;
}

// =============================================================================
// WEBSOCKET
// =============================================================================

function connectWebSocket() {
    if (App.socket) {
        App.socket.disconnect();
    }

    updateConnectionStatus('connecting');

    App.socket = io({ query: { token: App.token } });

    App.socket.on('connect', () => {
        console.log('[SOCKET] Connected');
        updateConnectionStatus('connected');
        App.socket.emit('get_online_users');
    });

    App.socket.on('disconnect', () => {
        console.log('[SOCKET] Disconnected');
        updateConnectionStatus('disconnected');
    });

    App.socket.on('connect_error', (error) => {
        console.error('[SOCKET] Connection error:', error);
        updateConnectionStatus('disconnected');
    });

    App.socket.on('user_online', (data) => {
        console.log('[SOCKET] User online:', data.username);
        App.onlineUsers.set(data.user_id, data);
        renderChatList();
        updateCurrentChatStatus();
    });

    App.socket.on('user_offline', (data) => {
        console.log('[SOCKET] User offline:', data.username);
        App.onlineUsers.delete(data.user_id);
        renderChatList();
        updateCurrentChatStatus();
    });

    App.socket.on('online_users_list', (data) => {
        console.log('[SOCKET] Online users:', data.users.length);
        App.onlineUsers.clear();
        data.users.forEach(user => App.onlineUsers.set(user.id, user));
        renderChatList();
    });

    App.socket.on('new_message', async (data) => {
        console.log('[SOCKET] New message from:', data.sender_username);
        handleIncomingMessage(data);
    });

    App.socket.on('message_sent', (data) => {
        console.log('[SOCKET] Message sent:', data.message_id);
    });

    App.socket.on('user_typing', (data) => {
        if (App.currentChat && App.currentChat.userId === data.user_id) {
            document.getElementById('typing-indicator').classList.remove('hidden');
        }
    });

    App.socket.on('user_stop_typing', (data) => {
        if (App.currentChat && App.currentChat.userId === data.user_id) {
            document.getElementById('typing-indicator').classList.add('hidden');
        }
    });

    App.socket.on('error', (data) => {
        console.error('[SOCKET] Error:', data.message);
        showToast(data.message, 'error');
    });
}

function handleIncomingMessage(data) {
    if (!data.timestamp) {
        data.timestamp = new Date().toISOString();
    }

    // Add to chats if new
    if (!App.chats.has(data.sender_id)) {
        App.chats.set(data.sender_id, {
            userId: data.sender_id,
            username: data.sender_username
        });
        renderChatList();
    }

    // Cache public key
    if (data.sender_public_key) {
        App.publicKeys.set(data.sender_id, data.sender_public_key);
    }

    // If chat is open, show message
    if (App.currentChat && App.currentChat.userId === data.sender_id) {
        // For encrypted messages, show placeholder (decryption would happen here)
        renderMessage(data, false, data.plaintext || '[Encrypted message]');
        
        const container = document.getElementById('messages-container');
        container.scrollTop = container.scrollHeight;
        document.getElementById('typing-indicator').classList.add('hidden');
    } else {
        showToast(`New message from ${data.sender_username}`, 'success');
    }
}

// =============================================================================
// NEW CHAT MODAL
// =============================================================================

async function openNewChatModal() {
    const modal = document.getElementById('new-chat-modal');
    const usersList = document.getElementById('online-users-list');

    modal.classList.remove('hidden');
    usersList.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> Loading users...</div>';

    App.socket.emit('get_online_users');

    try {
        const response = await fetch('/api/users/online', {
            headers: { 'Authorization': `Bearer ${App.token}` }
        });

        if (response.ok) {
            const users = await response.json();

            if (users.length === 0) {
                usersList.innerHTML = `
                    <div class="no-users-message">
                        <i class="fas fa-user-slash"></i>
                        <p>No other users online</p>
                    </div>
                `;
                return;
            }

            // Store users temporarily for click handling
            window._onlineUsers = {};
            users.forEach(user => {
                window._onlineUsers[user.id] = user;
            });

            let html = '';
            users.forEach(user => {
                html += `
                    <div class="online-user-item" data-user-id="${user.id}">
                        <div class="avatar">
                            <i class="fas fa-user"></i>
                            <span class="online-indicator"></span>
                        </div>
                        <span class="username">${escapeHtml(user.username)}</span>
                        <span class="status"><i class="fas fa-circle"></i> Online</span>
                    </div>
                `;
            });

            usersList.innerHTML = html;

            // Add click listeners
            usersList.querySelectorAll('.online-user-item').forEach(item => {
                item.addEventListener('click', () => {
                    const userId = parseInt(item.dataset.userId);
                    const user = window._onlineUsers[userId];
                    if (user) {
                        startNewChat(user.id, user.username, user.public_key);
                    }
                });
            });
        }
    } catch (error) {
        console.error('[APP] Failed to load online users:', error);
        usersList.innerHTML = '<div class="no-users-message"><p>Failed to load users</p></div>';
    }
}

function closeNewChatModal() {
    document.getElementById('new-chat-modal').classList.add('hidden');
}

async function startNewChat(userId, username, publicKey) {
    closeNewChatModal();

    try {
        const response = await fetch('/api/chats', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${App.token}`
            },
            body: JSON.stringify({ user_id: userId })
        });

        if (response.ok) {
            const data = await response.json();

            App.chats.set(userId, {
                chatId: data.chat_id,
                userId: userId,
                username: username,
                publicKey: publicKey || data.other_user.public_key
            });

            if (publicKey || data.other_user.public_key) {
                App.publicKeys.set(userId, publicKey || data.other_user.public_key);
            }

            renderChatList();
            openChat(userId);
        }
    } catch (error) {
        console.error('[APP] Failed to create chat:', error);
        showToast('Failed to start chat', 'error');
    }
}

// =============================================================================
// UI UTILITIES
// =============================================================================

function showChatInfo() {
    document.getElementById('my-public-key').value = App.user.public_key || 'Not available';
    document.getElementById('chat-info-modal').classList.remove('hidden');
}

function updateConnectionStatus(status) {
    const statusDot = document.querySelector('.status-dot');
    const statusText = document.querySelector('.status-text');

    statusDot.classList.remove('connected', 'disconnected');

    switch (status) {
        case 'connected':
            statusDot.classList.add('connected');
            statusText.textContent = 'Connected';
            break;
        case 'disconnected':
            statusDot.classList.add('disconnected');
            statusText.textContent = 'Disconnected';
            break;
        default:
            statusText.textContent = 'Connecting...';
    }
}

function updateCurrentChatStatus() {
    if (App.currentChat) {
        const isOnline = App.onlineUsers.has(App.currentChat.userId);
        const statusEl = document.getElementById('chat-status');
        statusEl.textContent = isOnline ? 'Online' : 'Offline';
        statusEl.classList.toggle('online', isOnline);
    }
}

function showToast(message, type = 'success') {
    const container = document.getElementById('toast-container');

    const icons = {
        success: 'fa-check-circle',
        error: 'fa-exclamation-circle',
        warning: 'fa-exclamation-triangle'
    };

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <i class="fas ${icons[type] || icons.success}"></i>
        <span>${escapeHtml(message)}</span>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = 'fadeOut 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
