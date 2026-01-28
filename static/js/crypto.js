/**
 * ST2504 Applied Cryptography - Client-Side Cryptography
 * =======================================================
 * 
 * Handles client-side decryption for end-to-end encryption:
 * - AES-256-CTR decryption (Charles)
 * - RSA-OAEP key decryption (Denise)
 * - RSA signature verification (Yong Cheng)
 * 
 * Uses Web Crypto API.
 */

// ==================== UTILITIES ====================

function base64ToBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

function bufferToString(buffer) {
    return new TextDecoder('utf-8').decode(buffer);
}

function pemToBuffer(pem) {
    const base64 = pem
        .replace(/-----BEGIN.*-----/, '')
        .replace(/-----END.*-----/, '')
        .replace(/\s/g, '');
    return base64ToBuffer(base64);
}

// ==================== KEY IMPORT ====================

async function importPrivateKey(privateKeyPem) {
    return await crypto.subtle.importKey(
        'pkcs8',
        pemToBuffer(privateKeyPem),
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['decrypt']
    );
}

async function importPublicKey(publicKeyPem) {
    return await crypto.subtle.importKey(
        'spki',
        pemToBuffer(publicKeyPem),
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['verify']
    );
}

// ==================== RSA-OAEP DECRYPTION (Denise) ====================

async function rsaDecrypt(encryptedKeyBase64, privateKey) {
    const encryptedKey = base64ToBuffer(encryptedKeyBase64);
    return await crypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        privateKey,
        encryptedKey
    );
}

// ==================== AES-256-CTR DECRYPTION (Charles) ====================

async function aesDecrypt(ciphertextBase64, ivBase64, aesKeyBuffer) {
    const aesKey = await crypto.subtle.importKey(
        'raw',
        aesKeyBuffer,
        { name: 'AES-CTR' },
        false,
        ['decrypt']
    );
    
    const ciphertext = base64ToBuffer(ciphertextBase64);
    const iv = base64ToBuffer(ivBase64);
    
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-CTR', counter: new Uint8Array(iv), length: 64 },
        aesKey,
        ciphertext
    );
    
    return bufferToString(decrypted);
}

// ==================== RSA SIGNATURE VERIFICATION (Yong Cheng) ====================

async function verifySignature(message, signatureBase64, publicKey) {
    const signature = base64ToBuffer(signatureBase64);
    const data = new TextEncoder().encode(message);
    
    return await crypto.subtle.verify(
        { name: 'RSASSA-PKCS1-v1_5' },
        publicKey,
        signature,
        data
    );
}

// ==================== MAIN DECRYPT FUNCTION ====================

/**
 * Decrypt an encrypted message
 * @param {Object} encryptedData - Contains encrypted_payload, encrypted_key, iv, signature
 * @param {string} privateKeyPem - Recipient's private key
 * @param {string} senderPublicKeyPem - Sender's public key for signature verification
 * @returns {Promise<{plaintext: string, signatureValid: boolean|null}>}
 */
async function decryptMessage(encryptedData, privateKeyPem, senderPublicKeyPem = null) {
    try {
        console.log('[CRYPTO] Decrypting message...');
        
        // 1. Import private key
        const privateKey = await importPrivateKey(privateKeyPem);
        
        // 2. Decrypt AES key using RSA-OAEP
        const aesKeyBuffer = await rsaDecrypt(encryptedData.encrypted_key, privateKey);
        console.log('[CRYPTO] AES key decrypted');
        
        // 3. Decrypt message using AES-256-CTR
        const plaintext = await aesDecrypt(
            encryptedData.encrypted_payload,
            encryptedData.iv,
            aesKeyBuffer
        );
        console.log('[CRYPTO] Message decrypted');
        
        // 4. Verify signature if public key provided
        let signatureValid = null;
        if (senderPublicKeyPem && encryptedData.signature) {
            try {
                const publicKey = await importPublicKey(senderPublicKeyPem);
                const payload = `${encryptedData.encrypted_payload}:${encryptedData.iv}`;
                signatureValid = await verifySignature(payload, encryptedData.signature, publicKey);
                console.log('[CRYPTO] Signature valid:', signatureValid);
            } catch (e) {
                console.error('[CRYPTO] Signature verification failed:', e);
                signatureValid = false;
            }
        }
        
        return { plaintext, signatureValid };
        
    } catch (error) {
        console.error('[CRYPTO] Decryption failed:', error);
        throw error;
    }
}

// Export for use in app.js
window.CryptoModule = { decryptMessage };
