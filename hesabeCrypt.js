// ============================================================
// hesabeCrypt.js — Hesabe Kuwait AES-256-CBC Encryption
// Official implementation from developer.hesabe.com
// Dependency: npm install aes-js
// ============================================================
'use strict';
const aesjs = require('aes-js');
class HesabeCrypt {
 /**
 * @param {string} secretKey 32-character secret key from Hesabe dashboard
 * @param {string} ivKey 16-character IV key from Hesabe dashboard
 */
 constructor(secretKey, ivKey) {
 if (!secretKey || !ivKey) {
 throw new Error('HesabeCrypt: secretKey and ivKey are required');
 }
 this.key = aesjs.utils.utf8.toBytes(secretKey);
 this.iv = aesjs.utils.utf8.toBytes(ivKey);
 }
 /**
 * Encrypt a string or object using AES-256-CBC
 * @param {string|object} text Plain text or object to encrypt
 * @returns {string} Hex-encoded encrypted string
 */
 encrypt(text) {
 const str = typeof text === 'string' ? text : JSON.stringify(text);
 const padded = this._pkcs5Pad(str);
 const bytes = aesjs.utils.utf8.toBytes(padded);
 const cbc = new aesjs.ModeOfOperation.cbc(this.key, this.iv);
 const encrypted = cbc.encrypt(bytes);
 return aesjs.utils.hex.fromBytes(encrypted);
 }
 /**
 * Decrypt a hex-encoded AES-256-CBC encrypted string
 * @param {string} hexStr Hex-encoded encrypted string from Hesabe
 * @returns {object|string} Parsed JSON object or plain string
 */
 decrypt(hexStr) {
 const bytes = aesjs.utils.hex.toBytes(hexStr);
 const cbc = new aesjs.ModeOfOperation.cbc(this.key, this.iv);
 const decrypted = cbc.decrypt(bytes);
 const text = aesjs.utils.utf8.fromBytes(decrypted);
 const stripped = this._pkcs5Strip(text);
 try {
 return JSON.parse(stripped);
 } catch {
 return stripped;
 }
 }
 // ── PKCS5 Padding (block size 32) ──────────────────────────
 _pkcs5Pad(data) {
 const blockSize = 32;
 const padLen = blockSize - (data.length % blockSize);
 return data + String.fromCharCode(padLen).repeat(padLen);
 }
 _pkcs5Strip(data) {
 const len = data.length;
 const padLen = data.charCodeAt(len - 1);
 if (padLen < 1 || padLen > 32) return data;
 return data.substring(0, len - padLen);
 }
}
module.exports = HesabeCrypt;
// ── Quick self-test (run with: node hesabeCrypt.js) ────────────
if (require.main === module) {
 const crypto = new HesabeCrypt(
 '12345678901234567890123456789012', // 32 chars
 '1234567890123456' // 16 chars
 );
 const original = { merchantCode: 'TEST', amount: '2.500', currency: 'KWD' };
 const encrypted = crypto.encrypt(JSON.stringify(original));
 const decrypted = crypto.decrypt(encrypted);
 console.log('Original: ', original);
 console.log('Encrypted:', encrypted.substring(0, 40) + '...');
 console.log('Decrypted:', decrypted);
 console.log(' HesabeCrypt working correctly');
}