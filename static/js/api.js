/**
 * API Service Module - Member 1
 * 
 * Handles all HTTP API calls to the backend server.
 * Provides a clean interface for REST operations.
 */

const ApiService = {
    token: null,

    /**
     * Set the authentication token for API calls
     * @param {string} token - JWT token
     */
    setToken(token) {
        this.token = token;
    },

    /**
     * Clear the authentication token
     */
    clearToken() {
        this.token = null;
    },

    /**
     * Get headers for API requests
     * @returns {Object} Headers object with Content-Type and Authorization
     */
    getHeaders() {
        const headers = { 'Content-Type': 'application/json' };
        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }
        return headers;
    },

    /**
     * Register a new user
     * @param {string} username 
     * @param {string} password 
     * @returns {Promise<{ok: boolean, data: Object}>}
     */
    async register(username, password) {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        return { ok: response.ok, data: await response.json() };
    },

    /**
     * Login user
     * @param {string} username 
     * @param {string} password 
     * @returns {Promise<{ok: boolean, data: Object}>}
     */
    async login(username, password) {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        return { ok: response.ok, data: await response.json() };
    },

    /**
     * Logout user
     * @returns {Promise<boolean>}
     */
    async logout() {
        try {
            const response = await fetch('/api/logout', {
                method: 'POST',
                headers: this.getHeaders()
            });
            return response.ok;
        } catch {
            return false;
        }
    },

    /**
     * Verify current token is valid
     * @returns {Promise<boolean>}
     */
    async verifyToken() {
        try {
            const response = await fetch('/api/me', {
                headers: this.getHeaders()
            });
            return response.ok;
        } catch {
            return false;
        }
    },

    /**
     * Get list of online users
     * @returns {Promise<Array>}
     */
    async getOnlineUsers() {
        const response = await fetch('/api/users/online', {
            headers: this.getHeaders()
        });
        if (response.ok) {
            return await response.json();
        }
        return [];
    },

    /**
     * Get a user's public key
     * @param {number} userId 
     * @returns {Promise<Object|null>}
     */
    async getUserPublicKey(userId) {
        const response = await fetch(`/api/users/${userId}/public-key`, {
            headers: this.getHeaders()
        });
        if (response.ok) {
            return await response.json();
        }
        return null;
    },

    /**
     * Get user's chat list
     * @returns {Promise<Array>}
     */
    async getChats() {
        const response = await fetch('/api/chats', {
            headers: this.getHeaders()
        });
        if (response.ok) {
            return await response.json();
        }
        return [];
    },

    /**
     * Create a new chat with another user
     * @param {number} userId 
     * @returns {Promise<{ok: boolean, data: Object}>}
     */
    async createChat(userId) {
        const response = await fetch('/api/chats', {
            method: 'POST',
            headers: this.getHeaders(),
            body: JSON.stringify({ user_id: userId })
        });
        return { ok: response.ok, data: await response.json() };
    },

    /**
     * Get messages for a chat
     * @param {number} userId - Other user's ID
     * @returns {Promise<Array>}
     */
    async getChatMessages(userId) {
        const response = await fetch(`/api/chats/${userId}/messages`, {
            headers: this.getHeaders()
        });
        if (response.ok) {
            return await response.json();
        }
        return [];
    }
};

// Export for use in other modules
window.ApiService = ApiService;
