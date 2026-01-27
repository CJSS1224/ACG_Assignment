/**
 * ST2504 Applied Cryptography - Chat API
 * 
 * API calls for chat-related endpoints.
 * 
 * Charles
 */

import { CONFIG } from '../core/config.js';
import { get, post } from './client.js';

/**
 * Get all chats for current user
 * @returns {Promise<{ok: boolean, data: Array}>}
 */
export async function getChats() {
    return get(CONFIG.API.CHATS);
}

/**
 * Create or get existing chat with user
 * @param {number} userId 
 * @returns {Promise<{ok: boolean, data: object}>}
 */
export async function createChat(userId) {
    return post(CONFIG.API.CHATS, { user_id: userId });
}

/**
 * Get messages for a chat (encrypted)
 * @param {number} userId - The other user's ID
 * @returns {Promise<{ok: boolean, data: Array}>}
 */
export async function getMessages(userId) {
    return post(`${CONFIG.API.CHATS}/${userId}/messages`, {});
}
