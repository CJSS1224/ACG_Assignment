/**
 * ST2504 Applied Cryptography - SecureChat Client
 * ================================================
 * 
 * Main client application:
 * - Authentication (Solomon)
 * - Chat management (Charles)
 * - Real-time messaging via WebSocket
 * - Client-side decryption using Web Crypto API
 * 
 * FILE ORGANIZATION:
 * 1. Application State
 * 2. Core Cryptographic Operations (PRESENT THIS)
 * 3. Message Handling with Decryption (PRESENT THIS)
 * 4. Socket Connection & Events
 * 5. UI Functions (below - less important for presentation)
 */

// ==================== APPLICATION STATE ====================

const App = {
    token: null,
    user: null,
    privateKey: null,
    socket: null,
    currentChat: null,
    chats: new Map(),
    onlineUsers: new Map(),
    publicKeys: new Map()
};

// =============================================================================
// SECTION 1: CORE CRYPTOGRAPHIC OPERATIONS (PRESENT THIS)
// =============================================================================

/**
 * Decrypt and display incoming message
 * 
 * CRYPTO FLOW:
 * 1. Receive encrypted message from server
 * 2. Call CryptoModule.decryptMessage() which:
 *    - RSA-OAEP decrypts the AES key (Denise)
 *    - AES-256-CTR decrypts the message (Charles)
 *    - RSA verifies the signature (Yong Cheng)
 * 3. Display decrypted plaintext
 */
async function handleIncomingMessage(data) {
    // Add sender to chats if new
    if (!App.chats.has(data.sender_id)) {
        App.chats.set(data.sender_id, {
            userId: data.sender_id,
            username: data.sender_username,
            publicKey: data.sender_public_key
        });
        App.publicKeys.set(data.sender_id, data.sender_public_key);
        renderChatList();
    }
    
    // If this chat is currently open, decrypt and display
    if (App.currentChat && App.currentChat.userId === data.sender_id) {
        try {
            const senderPublicKey = App.publicKeys.get(data.sender_id) || data.sender_public_key;
            
            // ========== DECRYPTION HAPPENS HERE ==========
            const decrypted = await CryptoModule.decryptMessage(
                data,                    // Encrypted message data
                App.privateKey,          // My RSA private key
                senderPublicKey          // Sender's public key (for signature verification)
            );
            // =============================================
            
            renderMessage(decrypted.plaintext, false, decrypted.signatureValid);
            $('messages-container').scrollTop = $('messages-container').scrollHeight;
            $('typing-indicator').classList.add('hidden');
        } catch (e) {
            console.error('[CRYPTO] Decryption failed:', e);
            renderMessage('[Decryption failed]', false, false);
        }
    } else {
        showToast(`New message from ${data.sender_username}`);
    }
}

/**
 * Send encrypted message
 * 
 * CRYPTO FLOW:
 * 1. Send plaintext + private key to server
 * 2. Server calls crypto_model.encrypt_message() which:
 *    - Generates random AES-256 key
 *    - AES-256-CTR encrypts the message (Charles)
 *    - RSA-OAEP encrypts the AES key (Denise)
 *    - RSA signs the ciphertext (Yong Cheng)
 *    - HMAC-SHA256 for integrity (Amir)
 * 3. Server stores encrypted message in database (Akash)
 */
function sendMessage() {
    const input = $('message-input');
    const text = input.value.trim();
    
    if (!text || !App.currentChat) return;
    
    // ========== SEND TO SERVER FOR ENCRYPTION ==========
    App.socket.emit('send_message', {
        recipient_id: App.currentChat.userId,
        plaintext: text,
        private_key: App.privateKey  // For signing
    });
    // ==================================================
    
    renderMessage(text, true, null);
    $('messages-container').scrollTop = $('messages-container').scrollHeight;
    input.value = '';
}

/**
 * Load and decrypt message history
 * 
 * CRYPTO FLOW:
 * For each message in history:
 * 1. Determine if I'm sender or recipient
 * 2. Use appropriate encrypted_key (sender or recipient)
 * 3. Decrypt using CryptoModule.decryptMessage()
 */
async function loadMessages(userId) {
    const container = $('messages-container');
    container.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> Loading...</div>';
    
    const { ok, data } = await api(`/api/chats/${userId}/messages`);
    if (!ok) {
        container.innerHTML = '<p style="text-align:center;color:#888;">Failed to load messages</p>';
        return;
    }
    
    container.innerHTML = '';
    
    for (const msg of data) {
        const isSent = msg.sender_id === App.user.id;
        const senderPublicKey = isSent ? null : (msg.sender_public_key || App.publicKeys.get(msg.sender_id));
        
        try {
            // ========== DECRYPTION FOR EACH MESSAGE ==========
            const decrypted = await CryptoModule.decryptMessage(
                {
                    encrypted_payload: msg.encrypted_payload,
                    // Use sender's key if I sent it, recipient's key if I received it
                    encrypted_key: isSent ? msg.encrypted_key_sender : msg.encrypted_key,
                    iv: msg.iv,
                    signature: msg.signature
                },
                App.privateKey,      // My private key to decrypt
                senderPublicKey      // Sender's public key to verify signature
            );
            // ================================================
            
            renderMessage(decrypted.plaintext, isSent, decrypted.signatureValid, msg.timestamp);
        } catch (e) {
            console.error('[CRYPTO] Decrypt failed:', e);
            renderMessage('[Decryption failed]', isSent, false, msg.timestamp);
        }
    }
    
    container.scrollTop = container.scrollHeight;
}

// =============================================================================
// SECTION 2: AUTHENTICATION (Solomon) - JWT & Session Management
// =============================================================================

/**
 * Login user
 * 
 * CRYPTO FLOW:
 * 1. Send username/password to server
 * 2. Server verifies password with bcrypt (Solomon)
 * 3. Server decrypts private key using PBKDF2 + AES (Denise)
 * 4. Server returns JWT token + decrypted private key
 */
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
    
    // Store session (includes decrypted private key)
    App.token = data.token;
    App.user = data.user;
    App.privateKey = data.private_key;  // RSA private key for decryption
    localStorage.setItem('session', JSON.stringify({ 
        token: data.token, 
        user: data.user, 
        privateKey: data.private_key 
    }));
    
    showToast('Login successful!');
    showChatScreen();
    connectSocket();
}

/**
 * Register new user
 * 
 * CRYPTO FLOW:
 * 1. Send username/password to server
 * 2. Server generates RSA-2048 keypair (Denise)
 * 3. Server hashes password with bcrypt (Solomon)
 * 4. Server encrypts private key with PBKDF2 + AES (Denise)
 * 5. Server stores in database (Akash)
 * 6. Server returns JWT token + private key
 */
async function register() {
    const username = $('reg-username').value.trim();
    const password = $('reg-password').value;
    const confirm = $('reg-confirm').value;
    
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
    
    // Store session (includes newly generated private key)
    App.token = data.token;
    App.user = data.user;
    App.privateKey = data.private_key;  // Newly generated RSA private key
    localStorage.setItem('session', JSON.stringify({ 
        token: data.token, 
        user: data.user, 
        privateKey: data.private_key 
    }));
    
    showToast('Registration successful! RSA keypair generated.');
    showChatScreen();
    connectSocket();
}

function logout() {
    App.token = null;
    App.user = null;
    App.privateKey = null;
    App.currentChat = null;
    App.chats.clear();
    App.onlineUsers.clear();
    
    if (App.socket) {
        App.socket.disconnect();
        App.socket = null;
    }
    
    localStorage.removeItem('session');
    
    $('auth-container').classList.remove('hidden');
    $('chat-container').classList.add('hidden');
    showToast('Logged out');
}

function restoreSession() {
    const saved = localStorage.getItem('session');
    if (!saved) return false;
    
    try {
        const { token, user, privateKey } = JSON.parse(saved);
        App.token = token;
        App.user = user;
        App.privateKey = privateKey;
        return true;
    } catch {
        return false;
    }
}

// =============================================================================
// SECTION 3: WEBSOCKET CONNECTION
// =============================================================================

function connectSocket() {
    App.socket = io({ query: { token: App.token } });
    
    App.socket.on('connect', () => {
        console.log('[SOCKET] Connected');
        $('connection-status').className = 'connection-status connected';
        $('connection-status').innerHTML = '<span class="status-dot"></span><span>Connected</span>';
        App.socket.emit('get_online_users');
    });
    
    App.socket.on('disconnect', () => {
        console.log('[SOCKET] Disconnected');
        $('connection-status').className = 'connection-status disconnected';
        $('connection-status').innerHTML = '<span class="status-dot"></span><span>Disconnected</span>';
    });
    
    // User presence events
    App.socket.on('user_online', (data) => {
        App.onlineUsers.set(data.user_id, data);
        if (data.public_key) {
            App.publicKeys.set(data.user_id, data.public_key);
        }
        renderChatList();
    });
    
    App.socket.on('user_offline', (data) => {
        App.onlineUsers.delete(data.user_id);
        renderChatList();
    });
    
    App.socket.on('online_users_list', (data) => {
        App.onlineUsers.clear();
        data.users.forEach(u => {
            App.onlineUsers.set(u.id, u);
            if (u.public_key) {
                App.publicKeys.set(u.id, u.public_key);
            }
        });
        renderChatList();
    });
    
    // Message events
    App.socket.on('new_message', handleIncomingMessage);
    App.socket.on('message_sent', (data) => console.log('[SOCKET] Message sent:', data.message_id));
    
    // Typing indicators
    App.socket.on('user_typing', (data) => {
        if (App.currentChat && App.currentChat.userId === data.user_id) {
            $('typing-indicator').classList.remove('hidden');
        }
    });
    
    App.socket.on('user_stop_typing', (data) => {
        if (App.currentChat && App.currentChat.userId === data.user_id) {
            $('typing-indicator').classList.add('hidden');
        }
    });
    
    App.socket.on('error', (data) => showToast(data.message, 'error'));
}

// =============================================================================
// SECTION 4: UI HELPER FUNCTIONS (Less important for presentation)
// =============================================================================

function $(id) {
    return document.getElementById(id);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showToast(message, type = 'success') {
    const container = $('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<i class="fas fa-${type === 'success' ? 'check' : 'exclamation'}-circle"></i> ${escapeHtml(message)}`;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
}

async function api(url, options = {}) {
    const headers = { 'Content-Type': 'application/json' };
    if (App.token) headers['Authorization'] = `Bearer ${App.token}`;
    
    const res = await fetch(url, { ...options, headers });
    const data = await res.json();
    return { ok: res.ok, data };
}

// =============================================================================
// SECTION 5: UI NAVIGATION & RENDERING
// =============================================================================

function showLogin() {
    $('login-form').classList.add('active');
    $('register-form').classList.remove('active');
}

function showRegister() {
    $('register-form').classList.add('active');
    $('login-form').classList.remove('active');
}

function showChatScreen() {
    $('auth-container').classList.add('hidden');
    $('chat-container').classList.remove('hidden');
    $('current-username').textContent = App.user.username;
    loadChats();
}

async function loadChats() {
    const { ok, data } = await api('/api/chats');
    if (!ok) return;
    
    App.chats.clear();
    data.forEach(c => {
        App.chats.set(c.other_user_id, {
            chatId: c.chat_id,
            userId: c.other_user_id,
            username: c.other_username,
            publicKey: c.other_public_key
        });
        App.publicKeys.set(c.other_user_id, c.other_public_key);
    });
    
    renderChatList();
}

function renderChatList() {
    const list = $('chat-list');
    
    if (App.chats.size === 0) {
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
    
    list.innerHTML = html;
}

async function openChat(userId) {
    const chat = App.chats.get(userId) || App.onlineUsers.get(userId);
    if (!chat) return;
    
    App.currentChat = {
        userId: userId,
        username: chat.username,
        publicKey: chat.publicKey || chat.public_key
    };
    
    if (App.currentChat.publicKey) {
        App.publicKeys.set(userId, App.currentChat.publicKey);
    }
    
    $('no-chat-selected').classList.add('hidden');
    $('active-chat').classList.remove('hidden');
    $('chat-username').textContent = App.currentChat.username;
    $('chat-status').textContent = App.onlineUsers.has(userId) ? 'Online' : 'Offline';
    
    renderChatList();
    await loadMessages(userId);
}

function renderMessage(text, isSent, signatureValid, timestamp) {
    const container = $('messages-container');
    
    let icon = '';
    if (isSent) {
        icon = '<i class="fas fa-check-circle" style="color:#4CAF50;" title="Sent"></i>';
    } else if (signatureValid === true) {
        icon = '<i class="fas fa-check-double" style="color:#4CAF50;" title="Signature verified"></i>';
    } else if (signatureValid === false) {
        icon = '<i class="fas fa-exclamation-triangle" style="color:#ff9800;" title="Signature invalid"></i>';
    } else {
        icon = '<i class="fas fa-lock" title="Encrypted"></i>';
    }
    
    const time = timestamp ? new Date(timestamp).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'}) : 'Now';
    
    const div = document.createElement('div');
    div.className = `message ${isSent ? 'sent' : 'received'}`;
    div.innerHTML = `
        <div class="message-content">${escapeHtml(text)}</div>
        <div class="message-meta">
            <span class="time">${time}</span>
            ${icon}
        </div>
    `;
    
    container.appendChild(div);
}

function handleKeyPress(e) {
    if (e.key === 'Enter') {
        sendMessage();
    } else if (App.currentChat) {
        App.socket.emit('typing', { recipient_id: App.currentChat.userId });
        clearTimeout(App.typingTimeout);
        App.typingTimeout = setTimeout(() => {
            App.socket.emit('stop_typing', { recipient_id: App.currentChat.userId });
        }, 1000);
    }
}

// =============================================================================
// SECTION 6: MODAL FUNCTIONS
// =============================================================================

function openNewChatModal() {
    $('new-chat-modal').classList.remove('hidden');
    
    const list = $('online-users-list');
    
    if (App.onlineUsers.size === 0) {
        list.innerHTML = '<div class="no-users"><i class="fas fa-user-slash"></i><p>No users online</p></div>';
        return;
    }
    
    let html = '';
    App.onlineUsers.forEach((user, id) => {
        if (id === App.user.id) return;
        if (user.public_key) {
            App.publicKeys.set(id, user.public_key);
        }
        html += `
            <div class="online-user-item" data-user-id="${id}" data-username="${escapeHtml(user.username)}">
                <div class="avatar"><i class="fas fa-user"></i><span class="online-indicator"></span></div>
                <span class="username">${escapeHtml(user.username)}</span>
            </div>
        `;
    });
    
    list.innerHTML = html || '<div class="no-users"><p>No other users online</p></div>';
    
    list.querySelectorAll('.online-user-item').forEach(item => {
        item.addEventListener('click', () => {
            const userId = parseInt(item.dataset.userId);
            const username = item.dataset.username;
            startChat(userId, username);
        });
    });
}

function closeModal() {
    $('new-chat-modal').classList.add('hidden');
    $('chat-info-modal').classList.add('hidden');
}

function startChat(userId, username) {
    const publicKey = App.publicKeys.get(userId) || '';
    
    if (!App.chats.has(userId)) {
        App.chats.set(userId, { userId, username, publicKey });
    }
    
    closeModal();
    renderChatList();
    openChat(userId);
}

function showChatInfo() {
    $('chat-info-modal').classList.remove('hidden');
    $('my-public-key').value = App.user.public_key;
}

function copyPublicKey() {
    $('my-public-key').select();
    document.execCommand('copy');
    showToast('Public key copied!');
}

// =============================================================================
// SECTION 7: INITIALIZATION
// =============================================================================

document.addEventListener('DOMContentLoaded', async () => {
    console.log('[APP] Initializing SecureChat...');
    
    // Restore session
    if (restoreSession()) {
        const { ok } = await api('/api/me');
        if (ok) {
            showChatScreen();
            connectSocket();
        } else {
            localStorage.removeItem('session');
        }
    }
    
    // Event listeners
    $('login-form').addEventListener('submit', (e) => { e.preventDefault(); login(); });
    $('register-form').addEventListener('submit', (e) => { e.preventDefault(); register(); });
    $('message-input').addEventListener('keypress', handleKeyPress);
    $('send-btn').addEventListener('click', sendMessage);
    $('logout-btn').addEventListener('click', logout);
    $('new-chat-btn').addEventListener('click', openNewChatModal);
    $('close-modal').addEventListener('click', closeModal);
    $('chat-info-btn').addEventListener('click', showChatInfo);
    $('close-info-modal').addEventListener('click', closeModal);
    $('copy-key-btn').addEventListener('click', copyPublicKey);
    $('show-register').addEventListener('click', (e) => { e.preventDefault(); showRegister(); });
    $('show-login').addEventListener('click', (e) => { e.preventDefault(); showLogin(); });
    
    $('new-chat-modal').addEventListener('click', (e) => { if (e.target.id === 'new-chat-modal') closeModal(); });
    $('chat-info-modal').addEventListener('click', (e) => { if (e.target.id === 'chat-info-modal') closeModal(); });
    
    console.log('[APP] Ready');
});
