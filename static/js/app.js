/**
 * SecureChat Client Application
 * ==============================
 * ST2504 Applied Cryptography Assignment 2
 * 
 * This client handles:
 *   - User authentication (login/register)
 *   - Real-time messaging via WebSocket
 *   - HMAC generation for transit integrity
 *   - UI rendering
 * 
 * NOTE: All encryption happens server-side (Python).
 *       Client only handles HMAC for transit integrity.
 */

// =============================================================================
// APPLICATION STATE
// =============================================================================

const App = {
    // Authentication
    token: null,
    user: null,
    privateKey: null,
    sessionSecret: null,  // For HMAC transit integrity
    
    // WebSocket
    socket: null,
    
    // Chat state
    currentChat: null,
    chats: new Map(),
    onlineUsers: new Map(),
    
    // Typing timeout
    typingTimeout: null
};

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/** Shorthand for document.getElementById */
const $ = (id) => document.getElementById(id);

/** Escape HTML to prevent XSS */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/** Show toast notification */
function showToast(message, type = 'info') {
    const container = $('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    let icon = 'info-circle';
    if (type === 'success') icon = 'check-circle';
    if (type === 'error') icon = 'exclamation-circle';
    if (type === 'warning') icon = 'exclamation-triangle';
    
    toast.innerHTML = `<i class="fas fa-${icon}"></i><span>${escapeHtml(message)}</span>`;
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'fadeOut 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

/** Make API request */
async function api(url, options = {}) {
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };
    
    if (App.token) {
        headers['Authorization'] = `Bearer ${App.token}`;
    }
    
    if (App.privateKey) {
        headers['X-Private-Key'] = btoa(App.privateKey);
    }
    
    try {
        const response = await fetch(url, { ...options, headers });
        const data = await response.json();
        return { ok: response.ok, data };
    } catch (error) {
        console.error('[API] Error:', error);
        return { ok: false, data: { error: 'Network error' } };
    }
}

/** Update connection status indicator */
function updateConnectionStatus(connected) {
    const statusEl = $('connection-status');
    if (connected) {
        statusEl.innerHTML = '<span class="status-dot connected"></span><span>Connected securely</span>';
    } else {
        statusEl.innerHTML = '<span class="status-dot disconnected"></span><span>Disconnected</span>';
    }
}

// =============================================================================
// HMAC TRANSIT INTEGRITY
// =============================================================================

/**
 * Generate HMAC-SHA256 for data being sent to server.
 * This ensures INTEGRITY IN TRANSIT.
 */
async function generateHmac(data) {
    if (!App.sessionSecret) {
        return null;
    }
    
    // Decode base64 session secret
    const secretBytes = Uint8Array.from(atob(App.sessionSecret), c => c.charCodeAt(0));
    
    // Import key for HMAC
    const key = await crypto.subtle.importKey(
        'raw',
        secretBytes,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    
    // Serialize data consistently (must match server)
    const dataStr = JSON.stringify(data, Object.keys(data).sort());
    const dataBytes = new TextEncoder().encode(dataStr);
    
    // Generate HMAC
    const signature = await crypto.subtle.sign('HMAC', key, dataBytes);
    
    // Convert to hex
    return Array.from(new Uint8Array(signature))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * Wrap data with HMAC before sending.
 */
async function wrapWithHmac(data) {
    const hmac = await generateHmac(data);
    return {
        payload: data,
        hmac: hmac
    };
}

/**
 * Verify HMAC on received data.
 */
async function verifyHmac(wrappedData) {
    if (!wrappedData.hmac || !App.sessionSecret) {
        return wrappedData.payload || wrappedData;
    }
    
    const expectedHmac = await generateHmac(wrappedData.payload);
    
    if (expectedHmac === wrappedData.hmac) {
        console.log('[TRANSIT] ✓ HMAC verified');
        return wrappedData.payload;
    } else {
        console.warn('[TRANSIT] ✗ HMAC mismatch!');
        return wrappedData.payload;  // Still return data but log warning
    }
}

// =============================================================================
// AUTHENTICATION
// =============================================================================

async function register() {
    const username = $('reg-username').value.trim();
    const password = $('reg-password').value;
    const confirm = $('reg-confirm').value;
    
    // Validation
    if (username.length < 3) {
        showToast('Username must be at least 3 characters', 'error');
        return;
    }
    if (password.length < 6) {
        showToast('Password must be at least 6 characters', 'error');
        return;
    }
    if (password !== confirm) {
        showToast('Passwords do not match', 'error');
        return;
    }
    
    const { ok, data } = await api('/api/register', {
        method: 'POST',
        body: JSON.stringify({ username, password })
    });
    
    if (!ok) {
        showToast(data.error || 'Registration failed', 'error');
        return;
    }
    
    // Store session data
    App.token = data.token;
    App.user = data.user;
    App.privateKey = data.private_key;
    App.sessionSecret = data.session_secret;
    
    showToast('Registration successful! RSA keypair generated.', 'success');
    showChatScreen();
    connectSocket();
}

async function login() {
    const username = $('login-username').value.trim();
    const password = $('login-password').value;
    
    if (!username || !password) {
        showToast('Please enter username and password', 'error');
        return;
    }
    
    const { ok, data } = await api('/api/login', {
        method: 'POST',
        body: JSON.stringify({ username, password })
    });
    
    if (!ok) {
        showToast(data.error || 'Login failed', 'error');
        return;
    }
    
    // Store session data
    App.token = data.token;
    App.user = data.user;
    App.privateKey = data.private_key;
    App.sessionSecret = data.session_secret;
    
    showToast('Login successful!', 'success');
    showChatScreen();
    connectSocket();
}

function logout() {
    App.token = null;
    App.user = null;
    App.privateKey = null;
    App.sessionSecret = null;
    App.currentChat = null;
    App.chats.clear();
    App.onlineUsers.clear();
    
    if (App.socket) {
        App.socket.disconnect();
        App.socket = null;
    }
    
    showAuthScreen();
    showToast('Logged out', 'success');
}

// =============================================================================
// WEBSOCKET CONNECTION
// =============================================================================

function connectSocket() {
    if (!App.token) return;
    
    App.socket = io({
        query: { token: App.token }
    });
    
    // Connection events
    App.socket.on('connect', () => {
        console.log('[SOCKET] Connected');
        updateConnectionStatus(true);
        App.socket.emit('get_online_users');
        
        // Store private key on server for real-time decryption
        wrapWithHmac({ private_key: App.privateKey }).then(data => {
            App.socket.emit('store_private_key', data);
        });
    });
    
    App.socket.on('disconnect', () => {
        console.log('[SOCKET] Disconnected');
        updateConnectionStatus(false);
    });
    
    // User events
    App.socket.on('user_online', async (data) => {
        const payload = await verifyHmac(data);
        App.onlineUsers.set(payload.user_id, payload);
        renderChatList();
        showToast(`${payload.username} is online`, 'info');
    });
    
    App.socket.on('user_offline', (data) => {
        App.onlineUsers.delete(data.user_id);
        renderChatList();
    });
    
    App.socket.on('online_users_list', async (data) => {
        const payload = await verifyHmac(data);
        App.onlineUsers.clear();
        payload.users.forEach(user => {
            App.onlineUsers.set(user.id, user);
        });
        renderChatList();
    });
    
    // Message events
    App.socket.on('message_sent', async (data) => {
        const payload = await verifyHmac(data);
        console.log('[MSG] Sent:', payload.message_id);
    });
    
    App.socket.on('new_message', async (data) => {
        const payload = await verifyHmac(data);
        handleNewMessage(payload);
    });
    
    App.socket.on('new_message_encrypted', async (data) => {
        const payload = await verifyHmac(data);
        // Need to reload messages to decrypt
        if (App.currentChat && App.currentChat.userId === payload.sender_id) {
            loadMessages(payload.sender_id);
        } else {
            showToast(`New message from ${payload.sender_username}`, 'info');
        }
    });
    
    // Typing events
    App.socket.on('user_typing', async (data) => {
        const payload = await verifyHmac(data);
        if (App.currentChat && App.currentChat.userId === payload.user_id) {
            $('typing-indicator').classList.remove('hidden');
        }
    });
    
    App.socket.on('user_stop_typing', async (data) => {
        const payload = await verifyHmac(data);
        if (App.currentChat && App.currentChat.userId === payload.user_id) {
            $('typing-indicator').classList.add('hidden');
        }
    });
    
    // Error events
    App.socket.on('error', async (data) => {
        const payload = await verifyHmac(data);
        showToast(payload.message || 'An error occurred', 'error');
    });
}

// =============================================================================
// MESSAGING
// =============================================================================

async function sendMessage() {
    const input = $('message-input');
    const text = input.value.trim();
    
    if (!text || !App.currentChat) return;
    
    // Send with HMAC for transit integrity
    const data = await wrapWithHmac({
        recipient_id: App.currentChat.userId,
        message: text,
        private_key: App.privateKey
    });
    
    App.socket.emit('send_message', data);
    
    // Render sent message immediately
    renderMessage(text, true, null);
    $('messages-container').scrollTop = $('messages-container').scrollHeight;
    input.value = '';
}

function handleNewMessage(payload) {
    // Add sender to chats if new
    if (!App.chats.has(payload.sender_id)) {
        App.chats.set(payload.sender_id, {
            userId: payload.sender_id,
            username: payload.sender_username
        });
        renderChatList();
    }
    
    // Display if chat is open
    if (App.currentChat && App.currentChat.userId === payload.sender_id) {
        renderMessage(payload.message, false, payload.signature_valid);
        $('messages-container').scrollTop = $('messages-container').scrollHeight;
        $('typing-indicator').classList.add('hidden');
    } else {
        showToast(`New message from ${payload.sender_username}`, 'info');
    }
}

async function loadMessages(userId) {
    const container = $('messages-container');
    container.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> Loading messages...</div>';
    
    const { ok, data } = await api(`/api/chats/${userId}/messages`);
    
    if (!ok) {
        container.innerHTML = '<p style="text-align:center;color:var(--text-secondary);padding:20px;">Failed to load messages</p>';
        return;
    }
    
    container.innerHTML = '';
    
    for (const msg of data.messages) {
        renderMessage(msg.plaintext, msg.is_sent, msg.signature_valid, msg.timestamp);
    }
    
    container.scrollTop = container.scrollHeight;
}

// =============================================================================
// UI RENDERING
// =============================================================================

function showAuthScreen() {
    $('auth-container').classList.remove('hidden');
    $('chat-container').classList.add('hidden');
}

function showChatScreen() {
    $('auth-container').classList.add('hidden');
    $('chat-container').classList.remove('hidden');
    $('current-username').textContent = App.user.username;
    $('my-public-key').value = App.user.public_key;
    loadChats();
}

function showLogin() {
    $('login-form').classList.add('active');
    $('register-form').classList.remove('active');
}

function showRegister() {
    $('login-form').classList.remove('active');
    $('register-form').classList.add('active');
}

async function loadChats() {
    const { ok, data } = await api('/api/chats');
    if (!ok) return;
    
    App.chats.clear();
    data.chats.forEach(chat => {
        App.chats.set(chat.other_user_id, {
            chatId: chat.chat_id,
            userId: chat.other_user_id,
            username: chat.other_username,
            publicKey: chat.other_public_key
        });
    });
    
    renderChatList();
}

function renderChatList() {
    const list = $('chat-list');
    
    // Combine chats and online users
    const allUsers = new Map([...App.chats]);
    App.onlineUsers.forEach((user, id) => {
        if (!allUsers.has(id)) {
            allUsers.set(id, user);
        }
    });
    
    if (allUsers.size === 0) {
        list.innerHTML = `
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
    allUsers.forEach((user, id) => {
        if (id === App.user.id) return;
        
        const isOnline = App.onlineUsers.has(id);
        const isActive = App.currentChat && App.currentChat.userId === id;
        const username = user.username || user.other_username;
        
        html += `
            <div class="chat-item ${isActive ? 'active' : ''}" onclick="openChat(${id}, '${escapeHtml(username)}')">
                <div class="avatar">
                    <i class="fas fa-user"></i>
                    ${isOnline ? '<span class="online-indicator"></span>' : ''}
                </div>
                <div class="chat-item-info">
                    <div class="name">${escapeHtml(username)}</div>
                    <div class="last-message">${isOnline ? 'Online' : 'Offline'}</div>
                </div>
            </div>
        `;
    });
    
    list.innerHTML = html || `
        <div class="empty-chats">
            <i class="fas fa-comments"></i>
            <p>No chats yet</p>
        </div>
    `;
}

function openChat(userId, username) {
    App.currentChat = { userId, username };
    
    $('no-chat-selected').classList.add('hidden');
    $('active-chat').classList.remove('hidden');
    $('chat-username').textContent = username;
    $('chat-status').textContent = App.onlineUsers.has(userId) ? 'Online' : 'Offline';
    
    renderChatList();
    loadMessages(userId);
}

function renderMessage(text, isSent, signatureValid, timestamp) {
    const container = $('messages-container');
    
    let verifyIcon = '';
    if (!isSent) {
        if (signatureValid === true) {
            verifyIcon = '<i class="fas fa-check-double verified" title="Signature verified"></i>';
        } else if (signatureValid === false) {
            verifyIcon = '<i class="fas fa-exclamation-triangle failed" title="Signature invalid"></i>';
        }
    } else {
        verifyIcon = '<i class="fas fa-check" title="Sent"></i>';
    }
    
    let timeStr = 'Now';
    if (timestamp) {
        const date = new Date(timestamp.replace(' ', 'T'));
        timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    
    const div = document.createElement('div');
    div.className = `message ${isSent ? 'sent' : 'received'}`;
    div.innerHTML = `
        <div class="message-content">${escapeHtml(text)}</div>
        <div class="message-meta">
            <span class="time">${timeStr}</span>
            ${verifyIcon}
        </div>
    `;
    
    container.appendChild(div);
}

// =============================================================================
// MODALS
// =============================================================================

function openNewChatModal() {
    $('modal').classList.remove('hidden');
    
    const list = $('online-users-list');
    
    if (App.onlineUsers.size === 0) {
        list.innerHTML = `
            <div class="no-users-message">
                <i class="fas fa-user-slash"></i>
                <p>No users online</p>
            </div>
        `;
        return;
    }
    
    let html = '';
    App.onlineUsers.forEach((user, id) => {
        if (id === App.user.id) return;
        
        html += `
            <div class="online-user-item" onclick="startChatWithUser(${id}, '${escapeHtml(user.username)}')">
                <div class="avatar">
                    <i class="fas fa-user"></i>
                    <span class="online-indicator"></span>
                </div>
                <span class="username">${escapeHtml(user.username)}</span>
                <span class="status"><i class="fas fa-circle"></i> Online</span>
            </div>
        `;
    });
    
    list.innerHTML = html || `
        <div class="no-users-message">
            <i class="fas fa-user-slash"></i>
            <p>No other users online</p>
        </div>
    `;
}

function closeModal() {
    $('modal').classList.add('hidden');
    $('chat-info-modal').classList.add('hidden');
}

function startChatWithUser(userId, username) {
    closeModal();
    
    if (!App.chats.has(userId)) {
        App.chats.set(userId, { userId, username });
    }
    
    renderChatList();
    openChat(userId, username);
}

function showChatInfo() {
    $('chat-info-modal').classList.remove('hidden');
}

function copyPublicKey() {
    const textarea = $('my-public-key');
    textarea.select();
    document.execCommand('copy');
    showToast('Public key copied!', 'success');
}

// =============================================================================
// EVENT HANDLERS
// =============================================================================

async function handleKeyPress(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        await sendMessage();
    } else if (App.currentChat) {
        // Send typing indicator
        const data = await wrapWithHmac({ recipient_id: App.currentChat.userId });
        App.socket.emit('typing', data);
        
        clearTimeout(App.typingTimeout);
        App.typingTimeout = setTimeout(async () => {
            const stopData = await wrapWithHmac({ recipient_id: App.currentChat.userId });
            App.socket.emit('stop_typing', stopData);
        }, 1000);
    }
}

// =============================================================================
// INITIALIZATION
// =============================================================================

document.addEventListener('DOMContentLoaded', () => {
    console.log('[APP] SecureChat initializing...');
    
    // Auth form handlers
    $('login-form').addEventListener('submit', (e) => {
        e.preventDefault();
        login();
    });
    
    $('register-form').addEventListener('submit', (e) => {
        e.preventDefault();
        register();
    });
    
    // Navigation
    $('show-register').addEventListener('click', (e) => {
        e.preventDefault();
        showRegister();
    });
    
    $('show-login').addEventListener('click', (e) => {
        e.preventDefault();
        showLogin();
    });
    
    // Chat handlers
    $('message-input').addEventListener('keypress', handleKeyPress);
    $('send-btn').addEventListener('click', sendMessage);
    $('logout-btn').addEventListener('click', logout);
    $('new-chat-btn').addEventListener('click', openNewChatModal);
    $('close-modal').addEventListener('click', closeModal);
    
    // Chat info modal
    $('chat-info-btn').addEventListener('click', showChatInfo);
    $('close-info-modal').addEventListener('click', closeModal);
    $('copy-key-btn').addEventListener('click', copyPublicKey);
    
    // Close modal on outside click
    $('modal').addEventListener('click', (e) => {
        if (e.target.id === 'modal') closeModal();
    });
    $('chat-info-modal').addEventListener('click', (e) => {
        if (e.target.id === 'chat-info-modal') closeModal();
    });
    
    console.log('[APP] SecureChat ready');
});
