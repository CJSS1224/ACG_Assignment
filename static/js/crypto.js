/**
 * ST2504 Applied Cryptography - Client-Side Cryptography Module
 * 
 * This module handles client-side decryption for end-to-end encryption:
 * - AES-256-CTR decryption (Charles)
 * - RSA-OAEP key decryption (Denise)
 * - RSA signature verification (Yong Cheng)
 * 
 * Uses Web Crypto API for all cryptographic operations.
 */

const CryptoModule = {
    
    // ==========================================================================
    // UTILITY FUNCTIONS
    // ==========================================================================
    
    /**
     * Convert Base64 string to ArrayBuffer
     */
    base64ToArrayBuffer(base64) {
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    },
    
    /**
     * Convert ArrayBuffer to string
     */
    arrayBufferToString(buffer) {
        const decoder = new TextDecoder('utf-8');
        return decoder.decode(buffer);
    },
    
    /**
     * Convert PEM to ArrayBuffer (strips headers and decodes Base64)
     */
    pemToArrayBuffer(pem) {
        // Remove PEM headers and newlines
        const base64 = pem
            .replace(/-----BEGIN.*-----/, '')
            .replace(/-----END.*-----/, '')
            .replace(/\s/g, '');
        return this.base64ToArrayBuffer(base64);
    },
    
    // ==========================================================================
    // RSA KEY IMPORT - Denise
    // ==========================================================================
    
    /**
     * Import RSA private key from PEM format for decryption
     */
    async importPrivateKey(privateKeyPem) {
        const keyData = this.pemToArrayBuffer(privateKeyPem);
        
        return await crypto.subtle.importKey(
            'pkcs8',
            keyData,
            {
                name: 'RSA-OAEP',
                hash: 'SHA-256'
            },
            false,
            ['decrypt']
        );
    },
    
    /**
     * Import RSA public key from PEM format for signature verification
     */
    async importPublicKeyForVerify(publicKeyPem) {
        const keyData = this.pemToArrayBuffer(publicKeyPem);
        
        return await crypto.subtle.importKey(
            'spki',
            keyData,
            {
                name: 'RSASSA-PKCS1-v1_5',
                hash: 'SHA-256'
            },
            false,
            ['verify']
        );
    },
    
    // ==========================================================================
    // RSA-OAEP DECRYPTION - Denise
    // ==========================================================================
    
    /**
     * Decrypt AES key using RSA-OAEP
     */
    async rsaDecrypt(encryptedKeyBase64, privateKey) {
        const encryptedKey = this.base64ToArrayBuffer(encryptedKeyBase64);
        
        const decryptedKey = await crypto.subtle.decrypt(
            { name: 'RSA-OAEP' },
            privateKey,
            encryptedKey
        );
        
        return decryptedKey;
    },
    
    // ==========================================================================
    // AES-256-CTR DECRYPTION - Charles
    // ==========================================================================
    
    /**
     * Decrypt message using AES-256-CTR
     */
    async aesDecrypt(ciphertextBase64, ivBase64, aesKeyBuffer) {
        // Import AES key
        const aesKey = await crypto.subtle.importKey(
            'raw',
            aesKeyBuffer,
            { name: 'AES-CTR' },
            false,
            ['decrypt']
        );
        
        const ciphertext = this.base64ToArrayBuffer(ciphertextBase64);
        const iv = this.base64ToArrayBuffer(ivBase64);
        
        // Decrypt using AES-CTR
        const decrypted = await crypto.subtle.decrypt(
            {
                name: 'AES-CTR',
                counter: new Uint8Array(iv),
                length: 64  // Counter bit length
            },
            aesKey,
            ciphertext
        );
        
        return this.arrayBufferToString(decrypted);
    },
    
    // ==========================================================================
    // RSA SIGNATURE VERIFICATION - Yong Cheng
    // ==========================================================================
    
    /**
     * Verify RSA signature
     */
    async verifySignature(message, signatureBase64, publicKey) {
        const signature = this.base64ToArrayBuffer(signatureBase64);
        const encoder = new TextEncoder();
        const data = encoder.encode(message);
        
        return await crypto.subtle.verify(
            { name: 'RSASSA-PKCS1-v1_5' },
            publicKey,
            signature,
            data
        );
    },
    
    // ==========================================================================
    // HIGH-LEVEL DECRYPTION - Charles
    // ==========================================================================
    
    /**
     * Decrypt a message using the recipient's private key
     * 
     * @param {Object} encryptedData - Contains encrypted_payload, encrypted_key, iv, signature
     * @param {string} privateKeyPem - Recipient's private key in PEM format
     * @param {string} senderPublicKeyPem - Sender's public key for signature verification (optional)
     * @returns {Object} - { plaintext, signatureValid }
     */
    async decryptMessage(encryptedData, privateKeyPem, senderPublicKeyPem = null) {
        try {
            console.log('[CRYPTO] Starting client-side decryption...');
            
            // 1. Import private key for RSA-OAEP decryption
            const privateKey = await this.importPrivateKey(privateKeyPem);
            
            // 2. Decrypt AES key using RSA-OAEP
            const aesKeyBuffer = await this.rsaDecrypt(encryptedData.encrypted_key, privateKey);
            console.log('[CRYPTO] AES key decrypted');
            
            // 3. Decrypt message using AES-256-CTR
            const plaintext = await this.aesDecrypt(
                encryptedData.encrypted_payload,
                encryptedData.iv,
                aesKeyBuffer
            );
            console.log('[CRYPTO] Message decrypted');
            
            // 4. Verify signature if public key provided
            let signatureValid = null;
            if (senderPublicKeyPem && encryptedData.signature) {
                try {
                    const publicKey = await this.importPublicKeyForVerify(senderPublicKeyPem);
                    const payloadToVerify = `${encryptedData.encrypted_payload}:${encryptedData.iv}`;
                    signatureValid = await this.verifySignature(
                        payloadToVerify,
                        encryptedData.signature,
                        publicKey
                    );
                    console.log('[CRYPTO] Signature verified:', signatureValid);
                } catch (sigError) {
                    console.error('[CRYPTO] Signature verification failed:', sigError);
                    signatureValid = false;
                }
            }
            
            return {
                plaintext,
                signatureValid
            };
            
        } catch (error) {
            console.error('[CRYPTO] Decryption failed:', error);
            throw error;
        }
    }
};

// Export for use in app.js
window.CryptoModule = CryptoModule;
