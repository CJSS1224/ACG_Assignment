/**
 * ST2504 Applied Cryptography - UI Rendering
 * 
 * Functions for rendering chat list and messages.
 * 
 * Charles
 */

import { App } from '../core/state.js';
import { CONFIG } from '../core/config.js';
import { $, setHtml } from './dom.js';
import { escapeHtml } from './escape.js';

/**
 * Render the chat list in the sidebar
 */
export function renderChatList() {
    const chatList = $(CONFIG.SELECTORS.CHAT_LIST);
    if (!chatList) return;

    if (App.chats.size === 0) {
        chatList.innerHTML = `
            <div class="empty-chats">
                <i class="fas fa-comments"></i>
                <p>No chats yet</p>
                <button onclick="window.SecureChat.openNewChatModal()" class="btn btn-secondary">
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
            <div class="chat-item ${isActive ? 'active' : ''}" onclick="window.SecureChat.openChat(${userId})">
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

/**
 * Render a single message in the chat
 * @param {object} msgData - Message data
 * @param {boolean} isSent - Whether message was sent by current user
 * @param {string} plaintext - Decrypted message text
 * @param {boolean|null} signatureValid - Signature verification result
 */
export function renderMessage(msgData, isSent, plaintext = null, signatureValid = null) {
    const container = $(CONFIG.SELECTORS.MESSAGES_CONTAINER);
    if (!container) return;

    const displayText = plaintext || '[Encrypted - loading...]';
    
    // Determine signature status icon
    let signatureStatus;
    if (isSent) {
        signatureStatus = '<i class="fas fa-check-circle verified" title="Sent"></i>';
    } else if (signatureValid === true) {
        signatureStatus = '<i class="fas fa-check-double verified" title="Signature verified" style="color: #4CAF50;"></i>';
    } else if (signatureValid === false) {
        signatureStatus = '<i class="fas fa-exclamation-triangle" title="Signature invalid" style="color: #ff9800;"></i>';
    } else {
        signatureStatus = '<i class="fas fa-lock" title="Encrypted"></i>';
    }

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

/**
 * Render online users list in modal
 * @param {Array} users - List of online users
 * @param {Function} onUserClick - Callback when user is clicked
 */
export function renderOnlineUsersList(users, onUserClick) {
    const usersList = $(CONFIG.SELECTORS.ONLINE_USERS_LIST);
    if (!usersList) return;

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
            const user = users.find(u => u.id === userId);
            if (user && onUserClick) {
                onUserClick(user);
            }
        });
    });
}

/**
 * Show loading state in messages container
 */
export function showMessagesLoading() {
    const container = $(CONFIG.SELECTORS.MESSAGES_CONTAINER);
    if (container) {
        container.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> Loading messages...</div>';
    }
}

/**
 * Show error state in messages container
 */
export function showMessagesError() {
    const container = $(CONFIG.SELECTORS.MESSAGES_CONTAINER);
    if (container) {
        container.innerHTML = '<p style="text-align: center; color: var(--text-secondary);">Failed to load messages</p>';
    }
}

/**
 * Clear messages container
 */
export function clearMessages() {
    const container = $(CONFIG.SELECTORS.MESSAGES_CONTAINER);
    if (container) {
        container.innerHTML = '';
    }
}

/**
 * Scroll messages container to bottom
 */
export function scrollMessagesToBottom() {
    const container = $(CONFIG.SELECTORS.MESSAGES_CONTAINER);
    if (container) {
        container.scrollTop = container.scrollHeight;
    }
}

/**
 * Show loading state in online users list
 */
export function showUsersLoading() {
    const usersList = $(CONFIG.SELECTORS.ONLINE_USERS_LIST);
    if (usersList) {
        usersList.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> Loading users...</div>';
    }
}
