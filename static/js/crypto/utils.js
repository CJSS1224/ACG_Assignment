/**
 * Crypto Utilities Module
 * 
 * Provides low-level utility functions for cryptographic operations:
 * - Base64 encoding/decoding
 * - Random byte generation
 * - PEM parsing
 */

const CryptoUtils = {
    /**
     * Convert ArrayBuffer to Base64 string
     * @param {ArrayBuffer} buffer - The buffer to convert
     * @returns {string} Base64 encoded string
     */
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    },

    /**
     * Convert Base64 string to ArrayBuffer
     * @param {string} base64 - Base64 encoded string
     * @returns {ArrayBuffer} Decoded buffer
     */
    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    },

    /**
     * Generate cryptographically secure random bytes
     * @param {number} length - Number of bytes to generate
     * @returns {Uint8Array} Random bytes
     */
    generateRandomBytes(length) {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return array;
    },

    /**
     * Extract Base64 content from PEM formatted string
     * @param {string} pem - PEM formatted key
     * @returns {string} Base64 content without headers
     */
    pemToBase64(pem) {
        const lines = pem.split('\n');
        let base64 = '';
        for (const line of lines) {
            if (!line.startsWith('-----')) {
                base64 += line.trim();
            }
        }
        return base64;
    }
};

// Export for use in other modules
window.CryptoUtils = CryptoUtils;
