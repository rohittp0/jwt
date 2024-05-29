const crypto = require('crypto');
const base64url = require('base64url');
const { generateKeyPairSync, publicEncrypt, privateDecrypt } = require('crypto');

// Generate RSA key pair (only once and store securely)
const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem'
  }
});
console.log('Public Key:', publicKey);
console.log('Private Key:', privateKey);

// Function to create a license
function createLicense(data, publicKey) {
  // Generate a random AES key
  const aesKey = crypto.randomBytes(32);

  // Encrypt the license data with AES
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
  let encryptedData = cipher.update(data, 'utf8', 'base64');
  encryptedData += cipher.final('base64');

  // Encrypt the AES key with RSA public key
  const encryptedAesKey = publicEncrypt(publicKey, aesKey);

  // Concatenate encrypted AES key, IV, and encrypted data
  const license = base64url.encode(Buffer.concat([encryptedAesKey, iv, Buffer.from(encryptedData, 'base64')]));

  return license;
}

// Function to verify and decrypt a license
function verifyLicense(license, privateKey) {
  // Decode the license from Base64 URL
  const decoded = base64url.toBuffer(license);

  // Extract the encrypted AES key, IV, and encrypted data
  const encryptedAesKey = decoded.slice(0, 256); // RSA 2048 bit key size is 256 bytes
  const iv = decoded.slice(256, 272); // IV is 16 bytes
  const encryptedData = decoded.slice(272).toString('base64');

  // Decrypt the AES key with RSA private key
  const aesKey = privateDecrypt(privateKey, encryptedAesKey);

  // Decrypt the license data with AES
  const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
  let decryptedData = decipher.update(encryptedData, 'base64', 'utf8');
  decryptedData += decipher.final('utf8');

  return decryptedData;
}

const domain = 'something.com';
const expirationDate = Math.floor((Date.now() + 1000 * 60 * 60 * 24 * 30) / 1000); // 30 days in seconds since epoch
const licenseData = `${domain}-${expirationDate}`;

const license = createLicense(licenseData, publicKey);
console.log('License:', license);

const decryptedData = verifyLicense(license, privateKey);
console.log('Decrypted Data:', decryptedData);
