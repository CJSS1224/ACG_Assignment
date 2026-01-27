/**
 * ST2504 Applied Cryptography - Chats Controller
 * 
 * Handles chat list loading, rendering, and chat opening.
 * 
 * Charles
 */

import { App, setCurrentChat, addChat, cachePublicKey } from '../core/state.js';
import { CONFIG } from '../core/config.js';
import { getChats } from '../api/chat.api.js';
import { renderChatList } from '../ui/render.js';
import { $, show, hide, setText, toggleClass, focus } from '../ui/dom.js';
import { loadMessages } from './messages.controller.js';

/**
 * Load all chats for current user
 */
export async function loadChats() {
    console.log('[CHATS] Loading chats...');
    
    try {
        const response = await getChats();
        console.log('[CHATS] Response status:', response.ok);
        
        if (response.ok) {
            const chats = response.data;
            console.log('[CHATS] Loaded chats:', chats);
            
            App.chats.clear();

            chats.forEach(chat => {
                console.log('[CHATS] Adding chat with user:', chat.other_user_id, chat.other_username);
                
                addChat(chat.other_user_id, {
                    chatId: chat.chat_id,
                    userId: chat.other_user_id,
                    username: chat.other_username,
                    publicKey: chat.other_public_key,
                    lastMessageAt: chat.last_message_at
                });

                cachePublicKey(chat.other_user_id, chat.other_public_key);
            });

            console.log('[CHATS] Total chats loaded:', App.chats.size);
            renderChatList();
        } else {
            console.error('[CHATS] Failed to load chats, status:', response.status);
        }
    } catch (error) {
        console.error('[CHATS] Failed to load chats:', error);
    }
}

/**
 * Open a chat with a specific user
 */
export async function openChat(userId) {
    const chat = App.chats.get(userId);
    if (!chat) return;

    setCurrentChat(chat);

    // Update UI
    hide(CONFIG.SELECTORS.NO_CHAT_SELECTED);
    show(CONFIG.SELECTORS.ACTIVE_CHAT);
    setText(CONFIG.SELECTORS.CHAT_USERNAME, chat.username);

    // Update online status
    const isOnline = App.onlineUsers.has(userId);
    const statusEl = $(CONFIG.SELECTORS.CHAT_STATUS);
    if (statusEl) {
        statusEl.textContent = isOnline ? 'Online' : 'Offline';
        statusEl.classList.toggle('online', isOnline);
    }

    // Refresh chat list to highlight active
    renderChatList();
    
    // Load messages
    await loadMessages(userId);
    
    // Focus input
    focus(CONFIG.SELECTORS.MESSAGE_INPUT);
}
