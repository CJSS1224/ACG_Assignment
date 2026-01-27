/**
 * ST2504 Applied Cryptography - Status Updates
 * 
 * Connection status and chat status UI updates.
 * 
 * Charles
 */

import { App } from '../core/state.js';
import { CONFIG } from '../core/config.js';
import { $, toggleClass, setText } from './dom.js';

/**
 * Update WebSocket connection status indicator
 * @param {string} status - 'connected' | 'disconnected' | 'connecting'
 */
export function updateConnectionStatus(status) {
    const statusDot = document.querySelector('.status-dot');
    const statusText = document.querySelector('.status-text');

    if (!statusDot || !statusText) return;

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

/**
 * Update current chat's online/offline status
 */
export function updateCurrentChatStatus() {
    if (!App.currentChat) return;

    const isOnline = App.onlineUsers.has(App.currentChat.userId);
    const statusEl = $(CONFIG.SELECTORS.CHAT_STATUS);
    
    if (statusEl) {
        statusEl.textContent = isOnline ? 'Online' : 'Offline';
        statusEl.classList.toggle('online', isOnline);
    }
}
