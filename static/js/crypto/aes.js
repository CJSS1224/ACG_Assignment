/**
 * AES Encryption Module - Member 3
 * 
 * Provides AES-256-CBC encryption and decryption functionality.
 * 
 * Security Property: CONFIDENTIALITY
 * - Messages are encrypted with 256-bit keys
 * - Each message uses a unique random IV
 * - Only parties with the key can decrypt
 */

const AESCrypto = {
    /**
     * Generate a random AES-256 key (32 bytes / 256 bits)
     * @returns {Uint8Array} Random key bytes
     */
    generateKey() {
        return CryptoUtils.generateRandomBytes(32);
    },

    /**
     * Generate a random IV for AES-CBC (16 bytes / 128 bits)
     * @returns {Uint8Array} Random IV bytes
     */
    generateIV() {
        return CryptoUtils.generateRandomBytes(16);
    },

    /**
     * Import raw key bytes as a CryptoKey for Web Crypto API
     * @param {Uint8Array} keyBytes - Raw key bytes
     * @returns {Promise<CryptoKey>} Imported key
     */
    async importKey(keyBytes) {
        return await crypto.subtle.importKey(
            'raw',
            keyBytes,
            { name: 'AES-CBC' },
            false,
            ['encrypt', 'decrypt']
        );
    },

    /**
     * Encrypt plaintext using AES-256-CBC
     * @param {string} plaintext - Text to encrypt
     * @param {Uint8Array} keyBytes - 32-byte AES key
     * @returns {Promise<{ciphertext: string, iv: string}>} Base64 encoded ciphertext and IV
     */
    async encrypt(plaintext, keyBytes) {
        const iv = this.generateIV();
        const key = await this.importKey(keyBytes);
        
        const encoder = new TextEncoder();
        const data = encoder.encode(plaintext);
        
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-CBC', iv: iv },
            key,
            data
        );
        
        return {
            ciphertext: CryptoUtils.arrayBufferToBase64(encrypted),
            iv: CryptoUtils.arrayBufferToBase64(iv)
        };
    },

    /**
     * Decrypt ciphertext using AES-256-CBC
     * @param {string} ciphertextBase64 - Base64 encoded ciphertext
     * @param {string} ivBase64 - Base64 encoded IV
     * @param {Uint8Array} keyBytes - 32-byte AES key
     * @returns {Promise<string>} Decrypted plaintext
     */
    async decrypt(ciphertextBase64, ivBase64, keyBytes) {
        const key = await this.importKey(keyBytes);
        const ciphertext = CryptoUtils.base64ToArrayBuffer(ciphertextBase64);
        const iv = CryptoUtils.base64ToArrayBuffer(ivBase64);
        
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-CBC', iv: new Uint8Array(iv) },
            key,
            ciphertext
        );
        
        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    }
};

// Export for use in other modules
window.AESCrypto = AESCrypto;
