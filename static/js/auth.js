/**
 * Authentication Module - Member 1
 * 
 * Handles user authentication:
 * - Login / Register / Logout
 * - Session management with localStorage
 * - Token validation
 */

const Auth = {
    user: null,
    token: null,

    /**
     * Initialize auth module - check for existing session
     * @returns {Promise<boolean>} True if valid session exists
     */
    async init() {
        const storedToken = localStorage.getItem('authToken');
        const storedUser = localStorage.getItem('loggedInUser');
        
        if (storedToken && storedUser) {
            this.token = storedToken;
            this.user = JSON.parse(storedUser);
            ApiService.setToken(storedToken);
            
            // Verify token is still valid
            const isValid = await ApiService.verifyToken();
            if (isValid) {
                return true;
            } else {
                this.clearSession();
                return false;
            }
        }
        return false;
    },

    /**
     * Handle user login
     * @param {string} username 
     * @param {string} password 
     * @returns {Promise<{success: boolean, error?: string}>}
     */
    async login(username, password) {
        const result = await ApiService.login(username, password);

        if (!result.ok) {
            return { success: false, error: result.data.error || 'Login failed' };
        }

        // Check if we have keys stored
        if (!CryptoHelper.hasKeys()) {
            return { success: false, error: 'Please register again - keys not found' };
        }

        // Store auth data
        this.token = result.data.token;
        this.user = result.data.user;
        this.saveSession();
        ApiService.setToken(this.token);

        return { success: true };
    },

    /**
     * Handle user registration
     * @param {string} username 
     * @param {string} password 
     * @returns {Promise<{success: boolean, error?: string}>}
     */
    async register(username, password) {
        const result = await ApiService.register(username, password);

        if (!result.ok) {
            return { success: false, error: result.data.error || 'Registration failed' };
        }

        // Store auth data
        this.token = result.data.token;
        this.user = {
            id: result.data.user_id,
            username: result.data.username,
            public_key: result.data.public_key
        };
        this.saveSession();
        ApiService.setToken(this.token);

        // Store crypto keys (received from server)
        CryptoHelper.storeKeys(result.data.private_key, result.data.public_key);

        return { success: true };
    },

    /**
     * Handle user logout
     */
    logout() {
        ApiService.logout();
        this.clearSession();
        // Note: We don't clear crypto keys - they persist for future logins on same device
    },

    /**
     * Save session to localStorage
     */
    saveSession() {
        localStorage.setItem('authToken', this.token);
        localStorage.setItem('loggedInUser', JSON.stringify(this.user));
    },

    /**
     * Clear session from localStorage
     */
    clearSession() {
        this.user = null;
        this.token = null;
        localStorage.removeItem('authToken');
        localStorage.removeItem('loggedInUser');
        ApiService.clearToken();
    },

    /**
     * Check if user is logged in
     * @returns {boolean}
     */
    isLoggedIn() {
        return !!(this.user && this.token);
    },

    /**
     * Get current user
     * @returns {Object|null}
     */
    getUser() {
        return this.user;
    },

    /**
     * Get current token
     * @returns {string|null}
     */
    getToken() {
        return this.token;
    }
};

// Export for use in other modules
window.Auth = Auth;
