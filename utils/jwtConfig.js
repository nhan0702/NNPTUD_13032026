const fs = require('fs');
const path = require('path');

const privateKeyPath = path.join(__dirname, '../keys/private.key');
const publicKeyPath = path.join(__dirname, '../keys/public.key');

// Đọc keys từ file
let privateKey, publicKey;

try {
    privateKey = fs.readFileSync(privateKeyPath, 'utf8');
    publicKey = fs.readFileSync(publicKeyPath, 'utf8');
} catch (error) {
    console.error('❌ Error reading keys:', error.message);
    console.error('Please run: node generateKeys.js in the root directory');
    process.exit(1);
}

// Cấu hình JWT JWT RS256
const jwtOptions = {
    algorithm: 'RS256',
    expiresIn: '30d'
};

module.exports = {
    privateKey,
    publicKey,
    jwtOptions
};
