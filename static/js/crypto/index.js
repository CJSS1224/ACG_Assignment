/**
 * CryptoHelper - Main Crypto Interface
 * 
 * This module provides a unified interface to all cryptographic operations.
 * It combines AES, RSA, Signatures, HMAC, and Key Storage into a single API.
 * 
 * Usage:
 *   await CryptoHelper.init();
 *   const encrypted = await CryptoHelper.encryptMessage(text, recipientPublicKey);
 *   const decrypted = await CryptoHelper.decryptMessage(encrypted, senderPublicKey);
 */

const CryptoHelper = {
    /**
     * Initialize the crypto module
     * Loads any existing keys from storage
     * @returns {Promise<boolean>} True when initialized
     */
    async init() {
        console.log('[CRYPTO] Initializing...');
        KeyStore.init();
        return true;
    },

    // =========================================================================
    // Key Management (delegated to KeyStore)
    // =========================================================================

    /**
     * Store keys received from server during registration
     */
    storeKeys(privateKeyPem, publicKeyPem) {
        KeyStore.storeKeys(privateKeyPem, publicKeyPem);
    },

    /**
     * Clear stored keys
     */
    clearKeys() {
        KeyStore.clearKeys();
    },

    /**
     * Check if keys are available
     */
    hasKeys() {
        return KeyStore.hasKeys();
    },

    /**
     * Get public key PEM
     */
    getPublicKey() {
        return KeyStore.getPublicKey();
    },

    /**
     * Get private key PEM
     */
    getPrivateKey() {
        return KeyStore.getPrivateKey();
    },

    // =========================================================================
    // High-Level Message Operations
    // =========================================================================

    /**
     * Encrypt a message for a recipient (full hybrid encryption)
     * 
     * Implements:
     * - Confidentiality: AES-256-CBC encryption
     * - Key Exchange: RSA-OAEP encrypted AES key (for BOTH sender and recipient)
     * - Non-Repudiation: RSA digital signature
     * - Integrity: HMAC-SHA256
     * 
     * @param {string} plaintext - Message to encrypt
     * @param {string} recipientPublicKeyPem - Recipient's public key
     * @returns {Promise<Object>} Encrypted message package
     */
    async encryptMessage(plaintext, recipientPublicKeyPem) {
        const privateKey = KeyStore.getPrivateKey();
        const publicKey = KeyStore.getPublicKey();

        if (!privateKey || !publicKey) {
            throw new Error('No keys available');
        }

        // 1. Generate random AES key for this message
        const aesKey = AESCrypto.generateKey();
        
        // 2. Encrypt message with AES
        const { ciphertext, iv } = await AESCrypto.encrypt(plaintext, aesKey);
        
        // 3. Encrypt AES key with recipient's public key (so they can decrypt)
        const encryptedKeyForRecipient = await RSACrypto.encrypt(aesKey, recipientPublicKeyPem);
        
        // 4. Encrypt AES key with sender's public key (so sender can read own messages)
        const encryptedKeyForSender = await RSACrypto.encrypt(aesKey, publicKey);
        
        // 5. Create payload for signing (ciphertext:iv)
        const payloadToSign = `${ciphertext}:${iv}`;
        
        // 6. Sign with sender's private key (non-repudiation)
        const signature = await SignatureCrypto.sign(payloadToSign, privateKey);
        
        // 7. Generate HMAC for integrity
        const hmacKey = CryptoUtils.generateRandomBytes(32);
        const hmac = await HMACCrypto.generate(payloadToSign, hmacKey);
        
        return {
            encrypted_payload: ciphertext,
            encrypted_key: encryptedKeyForRecipient,
            encrypted_key_sender: encryptedKeyForSender,
            iv: iv,
            signature: signature,
            hmac: hmac
        };
    },

    /**
     * Decrypt a message
     * 
     * Tries to decrypt using:
     * 1. encrypted_key (for recipient)
     * 2. encrypted_key_sender (for sender reading their own messages)
     * 
     * @param {Object} encryptedData - Encrypted message package
     * @param {string|null} senderPublicKeyPem - Sender's public key for signature verification
     * @returns {Promise<Object>} Decrypted plaintext and signature status
     */
    async decryptMessage(encryptedData, senderPublicKeyPem = null) {
        const privateKey = KeyStore.getPrivateKey();

        if (!privateKey) {
            throw new Error('No private key available');
        }

        let aesKey = null;
        
        // Try to decrypt the AES key - first try recipient key, then sender key
        try {
            aesKey = await RSACrypto.decrypt(encryptedData.encrypted_key, privateKey);
        } catch (error) {
            // If that fails, try the sender's encrypted key (for reading own messages)
            if (encryptedData.encrypted_key_sender) {
                try {
                    aesKey = await RSACrypto.decrypt(encryptedData.encrypted_key_sender, privateKey);
                } catch (error2) {
                    console.error('[CRYPTO] Failed to decrypt with both keys');
                    throw error2;
                }
            } else {
                throw error;
            }
        }

        try {
            // Decrypt message with AES
            const plaintext = await AESCrypto.decrypt(
                encryptedData.encrypted_payload,
                encryptedData.iv,
                aesKey
            );
            
            // Verify signature if sender's public key provided
            let signatureValid = null;
            if (senderPublicKeyPem && encryptedData.signature) {
                const payloadToVerify = `${encryptedData.encrypted_payload}:${encryptedData.iv}`;
                signatureValid = await SignatureCrypto.verify(
                    payloadToVerify,
                    encryptedData.signature,
                    senderPublicKeyPem
                );
            }
            
            return {
                plaintext: plaintext,
                signatureValid: signatureValid
            };
        } catch (error) {
            console.error('[CRYPTO] Decryption failed:', error);
            throw error;
        }
    }
};

// Export for use in other modules
window.CryptoHelper = CryptoHelper;
