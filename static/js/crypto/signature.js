/**
 * Digital Signature Module - Member 5
 * 
 * Provides RSA digital signature creation and verification.
 * 
 * Security Property: NON-REPUDIATION
 * - Sender cannot deny sending a message
 * - Anyone can verify using sender's public key
 * - Uses RSASSA-PKCS1-v1_5 with SHA-256
 */

const SignatureCrypto = {
    /**
     * Import RSA private key from PEM for signing
     * @param {string} pemString - PEM formatted private key
     * @returns {Promise<CryptoKey>} Imported private key for signing
     */
    async importPrivateKeyForSigning(pemString) {
        const base64 = CryptoUtils.pemToBase64(pemString);
        const binaryDer = CryptoUtils.base64ToArrayBuffer(base64);
        
        return await crypto.subtle.importKey(
            'pkcs8',
            binaryDer,
            {
                name: 'RSASSA-PKCS1-v1_5',
                hash: 'SHA-256'
            },
            false,
            ['sign']
        );
    },

    /**
     * Import RSA public key from PEM for verification
     * @param {string} pemString - PEM formatted public key
     * @returns {Promise<CryptoKey>} Imported public key for verification
     */
    async importPublicKeyForVerification(pemString) {
        const base64 = CryptoUtils.pemToBase64(pemString);
        const binaryDer = CryptoUtils.base64ToArrayBuffer(base64);
        
        return await crypto.subtle.importKey(
            'spki',
            binaryDer,
            {
                name: 'RSASSA-PKCS1-v1_5',
                hash: 'SHA-256'
            },
            false,
            ['verify']
        );
    },

    /**
     * Sign a message with RSA private key
     * Creates proof that the message came from the private key holder
     * @param {string} message - Message to sign
     * @param {string} privateKeyPem - Signer's PEM private key
     * @returns {Promise<string>} Base64 encoded signature
     */
    async sign(message, privateKeyPem) {
        const privateKey = await this.importPrivateKeyForSigning(privateKeyPem);
        const encoder = new TextEncoder();
        const data = encoder.encode(message);
        
        const signature = await crypto.subtle.sign(
            { name: 'RSASSA-PKCS1-v1_5' },
            privateKey,
            data
        );
        
        return CryptoUtils.arrayBufferToBase64(signature);
    },

    /**
     * Verify a message signature with RSA public key
     * Confirms the message came from the claimed sender
     * @param {string} message - Original message
     * @param {string} signatureBase64 - Base64 encoded signature
     * @param {string} publicKeyPem - Claimed signer's PEM public key
     * @returns {Promise<boolean>} True if signature is valid
     */
    async verify(message, signatureBase64, publicKeyPem) {
        try {
            const publicKey = await this.importPublicKeyForVerification(publicKeyPem);
            const encoder = new TextEncoder();
            const data = encoder.encode(message);
            const signature = CryptoUtils.base64ToArrayBuffer(signatureBase64);
            
            return await crypto.subtle.verify(
                { name: 'RSASSA-PKCS1-v1_5' },
                publicKey,
                signature,
                data
            );
        } catch (error) {
            console.error('[SIGNATURE] Verification failed:', error);
            return false;
        }
    }
};

// Export for use in other modules
window.SignatureCrypto = SignatureCrypto;
