/**
 * ST2504 Applied Cryptography - Socket Event Handlers
 * 
 * Handlers for WebSocket events.
 * 
 * Charles
 */

import { App, cachePublicKey, addChat } from '../core/state.js';
import { decryptMessage } from '../crypto/crypto.js';
import { renderChatList, renderMessage, scrollMessagesToBottom } from '../ui/render.js';
import { updateCurrentChatStatus } from '../ui/status.js';
import { showToast } from '../ui/toast.js';
import { $, hide } from '../ui/dom.js';
import { CONFIG } from '../core/config.js';

/**
 * Handle user coming online
 */
export function handleUserOnline(data) {
    console.log('[SOCKET] User online:', data.username);
    App.onlineUsers.set(data.user_id, data);
    renderChatList();
    updateCurrentChatStatus();
}

/**
 * Handle user going offline
 */
export function handleUserOffline(data) {
    console.log('[SOCKET] User offline:', data.username);
    App.onlineUsers.delete(data.user_id);
    renderChatList();
    updateCurrentChatStatus();
}

/**
 * Handle online users list update
 */
export function handleOnlineUsersList(data) {
    console.log('[SOCKET] Online users:', data.users.length);
    App.onlineUsers.clear();
    data.users.forEach(user => App.onlineUsers.set(user.id, user));
    renderChatList();
}

/**
 * Handle incoming encrypted message
 */
export async function handleIncomingMessage(data) {
    if (!data.timestamp) {
        data.timestamp = new Date().toISOString();
    }

    // Add to chats if new
    if (!App.chats.has(data.sender_id)) {
        addChat(data.sender_id, {
            userId: data.sender_id,
            username: data.sender_username
        });
        renderChatList();
    }

    // Cache sender's public key for signature verification
    if (data.sender_public_key) {
        cachePublicKey(data.sender_id, data.sender_public_key);
    }

    // If chat is open, decrypt and show message
    if (App.currentChat && App.currentChat.userId === data.sender_id) {
        if (data.encrypted_payload && App.privateKey) {
            try {
                // Client-side decryption using Web Crypto API
                const senderPublicKey = App.publicKeys.get(data.sender_id) || data.sender_public_key;
                const decrypted = await decryptMessage(
                    {
                        encrypted_payload: data.encrypted_payload,
                        encrypted_key: data.encrypted_key,
                        iv: data.iv,
                        signature: data.signature
                    },
                    App.privateKey,
                    senderPublicKey
                );
                
                renderMessage(data, false, decrypted.plaintext, decrypted.signatureValid);
            } catch (error) {
                console.error('[APP] Failed to decrypt message:', error);
                renderMessage(data, false, '[Decryption failed]', false);
            }
        } else if (data.plaintext) {
            renderMessage(data, false, data.plaintext);
        } else {
            renderMessage(data, false, '[Encrypted message - cannot decrypt]');
        }
        
        scrollMessagesToBottom();
        hide(CONFIG.SELECTORS.TYPING_INDICATOR);
    } else {
        showToast(`New message from ${data.sender_username}`, 'success');
    }
}

/**
 * Handle message sent confirmation
 */
export function handleMessageSent(data) {
    console.log('[SOCKET] Message sent:', data.message_id);
}

/**
 * Handle user typing indicator
 */
export function handleUserTyping(data) {
    if (App.currentChat && App.currentChat.userId === data.user_id) {
        const indicator = $(CONFIG.SELECTORS.TYPING_INDICATOR);
        if (indicator) indicator.classList.remove('hidden');
    }
}

/**
 * Handle user stop typing
 */
export function handleUserStopTyping(data) {
    if (App.currentChat && App.currentChat.userId === data.user_id) {
        hide(CONFIG.SELECTORS.TYPING_INDICATOR);
    }
}

/**
 * Handle socket error
 */
export function handleSocketError(data) {
    console.error('[SOCKET] Error:', data.message);
    showToast(data.message, 'error');
}
