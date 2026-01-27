/**
 * ST2504 Applied Cryptography - Modal Controller
 * 
 * Handles new chat modal and chat info modal.
 * 
 * Charles
 */

import { App, addChat, cachePublicKey } from '../core/state.js';
import { CONFIG } from '../core/config.js';
import { getOnlineUsers } from '../api/user.api.js';
import { createChat } from '../api/chat.api.js';
import { emitGetOnlineUsers } from '../socket/socket.client.js';
import { renderChatList, renderOnlineUsersList, showUsersLoading } from '../ui/render.js';
import { showToast } from '../ui/toast.js';
import { $, show, hide, setValue } from '../ui/dom.js';
import { openChat } from './chats.controller.js';

/**
 * Open the new chat modal
 */
export async function openNewChatModal() {
    show(CONFIG.SELECTORS.NEW_CHAT_MODAL);
    showUsersLoading();
    
    // Request fresh online users list
    emitGetOnlineUsers();

    try {
        const response = await getOnlineUsers();

        if (response.ok) {
            const users = response.data;
            
            renderOnlineUsersList(users, (user) => {
                startNewChat(user.id, user.username, user.public_key);
            });
        }
    } catch (error) {
        console.error('[MODAL] Failed to load online users:', error);
        const usersList = $(CONFIG.SELECTORS.ONLINE_USERS_LIST);
        if (usersList) {
            usersList.innerHTML = '<div class="no-users-message"><p>Failed to load users</p></div>';
        }
    }
}

/**
 * Close the new chat modal
 */
export function closeNewChatModal() {
    hide(CONFIG.SELECTORS.NEW_CHAT_MODAL);
}

/**
 * Start a new chat with a user
 */
async function startNewChat(userId, username, publicKey) {
    closeNewChatModal();

    try {
        const response = await createChat(userId);

        if (response.ok) {
            const data = response.data;

            addChat(userId, {
                chatId: data.chat_id,
                userId: userId,
                username: username,
                publicKey: publicKey || data.other_user.public_key
            });

            cachePublicKey(userId, publicKey || data.other_user.public_key);

            renderChatList();
            openChat(userId);
        }
    } catch (error) {
        console.error('[MODAL] Failed to create chat:', error);
        showToast('Failed to start chat', 'error');
    }
}

/**
 * Show chat info modal
 */
export function showChatInfo() {
    setValue(CONFIG.SELECTORS.MY_PUBLIC_KEY, App.user?.public_key || 'Not available');
    show(CONFIG.SELECTORS.CHAT_INFO_MODAL);
}

/**
 * Close chat info modal
 */
export function closeChatInfoModal() {
    hide(CONFIG.SELECTORS.CHAT_INFO_MODAL);
}

/**
 * Copy public key to clipboard
 */
export function copyPublicKey() {
    const textarea = $(CONFIG.SELECTORS.MY_PUBLIC_KEY);
    if (textarea) {
        textarea.select();
        document.execCommand('copy');
        showToast('Public key copied!', 'success');
    }
}
