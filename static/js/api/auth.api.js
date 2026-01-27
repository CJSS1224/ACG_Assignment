/**
 * ST2504 Applied Cryptography - Auth API
 * 
 * API calls for authentication endpoints.
 * 
 * Charles
 */

import { CONFIG } from '../core/config.js';
import { postPublic, get } from './client.js';

/**
 * Login user
 * @param {string} username 
 * @param {string} password 
 * @returns {Promise<{ok: boolean, data: object}>}
 */
export async function login(username, password) {
    return postPublic(CONFIG.API.LOGIN, { username, password });
}

/**
 * Register new user
 * @param {string} username 
 * @param {string} password 
 * @returns {Promise<{ok: boolean, data: object}>}
 */
export async function register(username, password) {
    return postPublic(CONFIG.API.REGISTER, { username, password });
}

/**
 * Verify current token validity
 * @returns {Promise<boolean>}
 */
export async function verifyToken() {
    try {
        const response = await get(CONFIG.API.ME);
        return response.ok;
    } catch {
        return false;
    }
}
