/**
 * ST2504 Applied Cryptography - Messages Controller
 * 
 * Handles message loading, sending, and decryption.
 * 
 * Charles
 */

import { App } from '../core/state.js';
import { CONFIG } from '../core/config.js';
import { getMessages } from '../api/chat.api.js';
import { decryptMessage } from '../crypto/crypto.js';
import { emitSendMessage, emitTyping, emitStopTyping } from '../socket/socket.client.js';
import { 
    renderMessage, 
    showMessagesLoading, 
    showMessagesError, 
    clearMessages,
    scrollMessagesToBottom 
} from '../ui/render.js';
import { showToast } from '../ui/toast.js';
import { $, setValue } from '../ui/dom.js';

// Typing timeout reference
let typingTimeout = null;

/**
 * Load and decrypt messages for a chat
 */
export async function loadMessages(userId) {
    showMessagesLoading();

    try {
        const response = await getMessages(userId);

        if (response.ok) {
            const messages = response.data;
            clearMessages();

            // Decrypt each message on client-side
            for (const msg of messages) {
                const isSent = msg.sender_id === App.user.id;
                
                if (msg.encrypted_payload && App.privateKey) {
                    try {
                        // Client-side decryption
                        const decrypted = await decryptMessage(
                            {
                                encrypted_payload: msg.encrypted_payload,
                                encrypted_key: msg.encrypted_key,
                                iv: msg.iv,
                                signature: msg.signature
                            },
                            App.privateKey,
                            msg.sender_public_key
                        );
                        
                        renderMessage(msg, isSent, decrypted.plaintext, decrypted.signatureValid);
                    } catch (decryptError) {
                        console.error('[MESSAGES] Failed to decrypt message:', msg.id, decryptError);
                        renderMessage(msg, isSent, '[Decryption failed]', false);
                    }
                } else {
                    renderMessage(msg, isSent, '[No encryption data]');
                }
            }

            scrollMessagesToBottom();
        }
    } catch (error) {
        console.error('[MESSAGES] Failed to load messages:', error);
        showMessagesError();
    }
}

/**
 * Send a message to the current chat
 */
export function sendMessage() {
    const input = $(CONFIG.SELECTORS.MESSAGE_INPUT);
    const text = input?.value.trim();

    if (!text || !App.currentChat) return;

    if (!App.privateKey) {
        showToast('Private key not available. Please login again.', 'error');
        return;
    }

    // Send message via WebSocket
    emitSendMessage(App.currentChat.userId, text, App.privateKey);

    // Clear input
    setValue(CONFIG.SELECTORS.MESSAGE_INPUT, '');

    // Show sent message immediately (optimistic update)
    const msgData = {
        timestamp: new Date().toISOString(),
        sender_id: App.user.id
    };
    renderMessage(msgData, true, text);
    scrollMessagesToBottom();
}

/**
 * Handle typing in message input
 */
export function handleTypingInput() {
    if (!App.currentChat || !App.socket) return;
    
    emitTyping(App.currentChat.userId);
    
    // Clear existing timeout
    if (typingTimeout) {
        clearTimeout(typingTimeout);
    }
    
    // Set new timeout to stop typing
    typingTimeout = setTimeout(() => {
        emitStopTyping(App.currentChat.userId);
    }, CONFIG.TIMING.TYPING_TIMEOUT);
}

/**
 * Handle Enter key in message input
 */
export function handleMessageKeypress(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        sendMessage();
    }
}
