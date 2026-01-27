/**
 * ST2504 Applied Cryptography - Storage Helpers
 * 
 * Utilities for localStorage operations.
 * 
 * Charles
 */

import { STORAGE_KEYS } from './config.js';

/**
 * Get authentication token from storage
 */
export function getToken() {
    return localStorage.getItem(STORAGE_KEYS.AUTH_TOKEN);
}

/**
 * Set authentication token in storage
 */
export function setToken(token) {
    localStorage.setItem(STORAGE_KEYS.AUTH_TOKEN, token);
}

/**
 * Remove authentication token from storage
 */
export function removeToken() {
    localStorage.removeItem(STORAGE_KEYS.AUTH_TOKEN);
}

/**
 * Get logged in user from storage
 */
export function getUser() {
    const stored = localStorage.getItem(STORAGE_KEYS.LOGGED_IN_USER);
    return stored ? JSON.parse(stored) : null;
}

/**
 * Set logged in user in storage
 */
export function setUser(user) {
    localStorage.setItem(STORAGE_KEYS.LOGGED_IN_USER, JSON.stringify(user));
}

/**
 * Remove logged in user from storage
 */
export function removeUser() {
    localStorage.removeItem(STORAGE_KEYS.LOGGED_IN_USER);
}

/**
 * Get private key from storage
 */
export function getPrivateKey() {
    return localStorage.getItem(STORAGE_KEYS.PRIVATE_KEY);
}

/**
 * Set private key in storage
 */
export function setPrivateKey(privateKey) {
    localStorage.setItem(STORAGE_KEYS.PRIVATE_KEY, privateKey);
}

/**
 * Remove private key from storage
 */
export function removePrivateKey() {
    localStorage.removeItem(STORAGE_KEYS.PRIVATE_KEY);
}

/**
 * Store complete session data
 */
export function saveSession(token, user, privateKey) {
    setToken(token);
    setUser(user);
    setPrivateKey(privateKey);
}

/**
 * Clear session data (except private key for re-login)
 */
export function clearSession() {
    removeToken();
    removeUser();
    // Note: Keep privateKey for future logins on same device
}

/**
 * Get all stored session data
 */
export function getStoredSession() {
    return {
        token: getToken(),
        user: getUser(),
        privateKey: getPrivateKey()
    };
}
