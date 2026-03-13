// Script để sinh RSA keys cho JWT RS256
// Chạy: node generateKeys.js

const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

// Tạo folder keys nếu chưa tồn tại
const keysDir = path.join(__dirname, 'keys');
if (!fs.existsSync(keysDir)) {
    fs.mkdirSync(keysDir);
    console.log('✅ Created keys folder');
}

// Generate RSA key pair
console.log('🔐 Generating RSA 2048 key pair...');
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
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

// Lưu private key
const privateKeyPath = path.join(keysDir, 'private.key');
fs.writeFileSync(privateKeyPath, privateKey);
console.log(`✅ Private key saved to: ${privateKeyPath}`);

// Lưu public key
const publicKeyPath = path.join(keysDir, 'public.key');
fs.writeFileSync(publicKeyPath, publicKey);
console.log(`✅ Public key saved to: ${publicKeyPath}`);

console.log('\n📋 Next steps:');
console.log('1. Create utils/jwtConfig.js');
console.log('2. Update routes/auth.js to use privateKey');
console.log('3. Update utils/authHandler.js to use publicKey');
console.log('4. Restart app: npm start');
console.log('\n⚠️  IMPORTANT: Add keys/private.key to .gitignore!');
