/**
 * Vulnerable Node.js Demo Service for ECDAT Evaluation.
 */

const crypto = require('crypto');

// Planted Artefact 9: Hardcoded secret key
const api_secret = "d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8";

function hashUserPassword(password) {
    // Planted Artefact 10: MD5 hash in Node.js
    return crypto.createHash('md5').update(password).digest('hex');
}

function encryptPayload(data, key, iv) {
    // Planted Artefact 11: AES-128 in CBC mode (weakened by Grover's algorithm to 64-bit)
    const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
    return Buffer.concat([cipher.update(data), cipher.final()]);
}

function generateEnterpriseKeys() {
    // Planted Artefact 12: RSA 2048-bit keypair (vulnerable to Shor's algorithm)
    return crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
}

module.exports = {
    hashUserPassword,
    encryptPayload,
    generateEnterpriseKeys
};
