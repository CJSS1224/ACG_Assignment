/**
 * HMAC Module - Member 4
 * 
 * Provides HMAC-SHA256 for message integrity verification.
 * 
 * Security Property: INTEGRITY
 * - Detects if message was modified in transit
 * - Requires shared secret key to generate/verify
 */

const HMACCrypto = {
    /**
     * Generate HMAC-SHA256 for a message
     * @param {string} message - Message to authenticate
     * @param {Uint8Array} keyBytes - HMAC key (32 bytes recommended)
     * @returns {Promise<string>} Base64 encoded HMAC
     */
    async generate(message, keyBytes) {
        const key = await crypto.subtle.importKey(
            'raw',
            keyBytes,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );
        
        const encoder = new TextEncoder();
        const data = encoder.encode(message);
        
        const signature = await crypto.subtle.sign('HMAC', key, data);
        return CryptoUtils.arrayBufferToBase64(signature);
    },

    /**
     * Verify HMAC-SHA256 for a message
     * @param {string} message - Original message
     * @param {string} hmacBase64 - Base64 encoded HMAC to verify
     * @param {Uint8Array} keyBytes - HMAC key
     * @returns {Promise<boolean>} True if HMAC is valid
     */
    async verify(message, hmacBase64, keyBytes) {
        try {
            const expectedHmac = await this.generate(message, keyBytes);
            return expectedHmac === hmacBase64;
        } catch (error) {
            console.error('[HMAC] Verification failed:', error);
            return false;
        }
    }
};

// Export for use in other modules
window.HMACCrypto = HMACCrypto;
