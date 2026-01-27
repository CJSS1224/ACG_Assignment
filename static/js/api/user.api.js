/**
 * ST2504 Applied Cryptography - User API
 * 
 * API calls for user-related endpoints.
 * 
 * Charles
 */

import { CONFIG } from '../core/config.js';
import { get } from './client.js';

/**
 * Get list of online users
 * @returns {Promise<{ok: boolean, data: Array}>}
 */
export async function getOnlineUsers() {
    return get(CONFIG.API.USERS_ONLINE);
}
