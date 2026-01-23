/**
 * RSA Encryption Module - Member 6
 * 
 * Provides RSA-OAEP encryption and decryption for key exchange.
 * 
 * Security Property: SECURE KEY EXCHANGE
 * - AES session keys are encrypted with recipient's public key
 * - Only the private key holder can decrypt
 * - Uses OAEP padding for security
 */

const RSACrypto = {
    /**
     * Import RSA public key from PEM for encryption
     * @param {string} pemString - PEM formatted public key
     * @returns {Promise<CryptoKey>} Imported public key
     */
    async importPublicKey(pemString) {
        const base64 = CryptoUtils.pemToBase64(pemString);
        const binaryDer = CryptoUtils.base64ToArrayBuffer(base64);
        
        return await crypto.subtle.importKey(
            'spki',
            binaryDer,
            {
                name: 'RSA-OAEP',
                hash: 'SHA-256'
            },
            false,
            ['encrypt']
        );
    },

    /**
     * Import RSA private key from PEM for decryption
     * @param {string} pemString - PEM formatted private key
     * @returns {Promise<CryptoKey>} Imported private key
     */
    async importPrivateKey(pemString) {
        const base64 = CryptoUtils.pemToBase64(pemString);
        const binaryDer = CryptoUtils.base64ToArrayBuffer(base64);
        
        return await crypto.subtle.importKey(
            'pkcs8',
            binaryDer,
            {
                name: 'RSA-OAEP',
                hash: 'SHA-256'
            },
            false,
            ['decrypt']
        );
    },

    /**
     * Encrypt data with RSA public key (RSA-OAEP)
     * Used for encrypting AES session keys
     * @param {Uint8Array} data - Data to encrypt (typically AES key)
     * @param {string} publicKeyPem - Recipient's PEM public key
     * @returns {Promise<string>} Base64 encoded encrypted data
     */
    async encrypt(data, publicKeyPem) {
        const publicKey = await this.importPublicKey(publicKeyPem);
        
        const encrypted = await crypto.subtle.encrypt(
            { name: 'RSA-OAEP' },
            publicKey,
            data
        );
        
        return CryptoUtils.arrayBufferToBase64(encrypted);
    },

    /**
     * Decrypt data with RSA private key (RSA-OAEP)
     * Used for decrypting AES session keys
     * @param {string} encryptedBase64 - Base64 encoded encrypted data
     * @param {string} privateKeyPem - Own PEM private key
     * @returns {Promise<Uint8Array>} Decrypted data (typically AES key)
     */
    async decrypt(encryptedBase64, privateKeyPem) {
        const privateKey = await this.importPrivateKey(privateKeyPem);
        const encrypted = CryptoUtils.base64ToArrayBuffer(encryptedBase64);
        
        const decrypted = await crypto.subtle.decrypt(
            { name: 'RSA-OAEP' },
            privateKey,
            encrypted
        );
        
        return new Uint8Array(decrypted);
    }
};

// Export for use in other modules
window.RSACrypto = RSACrypto;
