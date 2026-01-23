/**
 * Key Storage Module - Member 6
 * 
 * Manages storage and retrieval of cryptographic keys.
 * Uses localStorage for persistence (simplified for assignment).
 * 
 * In production, consider:
 * - IndexedDB with encryption
 * - Hardware security modules
 * - Secure enclave storage
 */

const KeyStore = {
    // Storage keys
    PRIVATE_KEY_STORAGE: 'secure_chat_private_key',
    PUBLIC_KEY_STORAGE: 'secure_chat_public_key',

    // In-memory cache
    privateKeyPem: null,
    publicKeyPem: null,

    /**
     * Initialize keystore and load any existing keys
     * @returns {boolean} True if keys were loaded
     */
    init() {
        console.log('[KEYSTORE] Initializing...');
        
        const storedPrivate = localStorage.getItem(this.PRIVATE_KEY_STORAGE);
        const storedPublic = localStorage.getItem(this.PUBLIC_KEY_STORAGE);
        
        if (storedPrivate && storedPublic) {
            console.log('[KEYSTORE] Found stored keys');
            this.privateKeyPem = storedPrivate;
            this.publicKeyPem = storedPublic;
            return true;
        }
        
        console.log('[KEYSTORE] No stored keys found');
        return false;
    },

    /**
     * Store keys received from server during registration
     * @param {string} privateKeyPem - PEM formatted private key
     * @param {string} publicKeyPem - PEM formatted public key
     */
    storeKeys(privateKeyPem, publicKeyPem) {
        this.privateKeyPem = privateKeyPem;
        this.publicKeyPem = publicKeyPem;
        localStorage.setItem(this.PRIVATE_KEY_STORAGE, privateKeyPem);
        localStorage.setItem(this.PUBLIC_KEY_STORAGE, publicKeyPem);
        console.log('[KEYSTORE] Keys stored');
    },

    /**
     * Clear all stored keys (used on logout if needed)
     */
    clearKeys() {
        this.privateKeyPem = null;
        this.publicKeyPem = null;
        localStorage.removeItem(this.PRIVATE_KEY_STORAGE);
        localStorage.removeItem(this.PUBLIC_KEY_STORAGE);
        console.log('[KEYSTORE] Keys cleared');
    },

    /**
     * Check if keys are available
     * @returns {boolean} True if both keys exist
     */
    hasKeys() {
        return !!(this.privateKeyPem && this.publicKeyPem);
    },

    /**
     * Get the public key PEM
     * @returns {string|null} Public key or null
     */
    getPublicKey() {
        return this.publicKeyPem;
    },

    /**
     * Get the private key PEM
     * @returns {string|null} Private key or null
     */
    getPrivateKey() {
        return this.privateKeyPem;
    }
};

// Export for use in other modules
window.KeyStore = KeyStore;
