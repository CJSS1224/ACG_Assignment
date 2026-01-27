/**
 * ST2504 Applied Cryptography - Application State
 * 
 * Centralized state management for the SecureChat application.
 * All modules import state from here to ensure consistency.
 * 
 * Charles
 */

export const App = {
    user: null,
    token: null,
    socket: null,
    currentChat: null,
    privateKey: null,
    chats: new Map(),
    onlineUsers: new Map(),
    publicKeys: new Map()
};

/**
 * Reset all application state (used on logout)
 */
export function resetState() {
    App.user = null;
    App.token = null;
    App.currentChat = null;
    App.chats.clear();
    App.onlineUsers.clear();
    // Note: privateKey and socket handled separately
}

/**
 * Set authenticated user data
 */
export function setAuthData(token, user, privateKey) {
    App.token = token;
    App.user = user;
    App.privateKey = privateKey;
}

/**
 * Set current active chat
 */
export function setCurrentChat(chat) {
    App.currentChat = chat;
}

/**
 * Add or update a chat
 */
export function addChat(userId, chatData) {
    App.chats.set(userId, chatData);
}

/**
 * Cache a user's public key
 */
export function cachePublicKey(userId, publicKey) {
    if (publicKey) {
        App.publicKeys.set(userId, publicKey);
    }
}

/**
 * Get cached public key for a user
 */
export function getPublicKey(userId) {
    return App.publicKeys.get(userId);
}
