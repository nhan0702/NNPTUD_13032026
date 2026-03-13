# 🔐 Hướng Dẫn Chuyển JWT từ HS256 sang RS256

## 📚 Giải Thích Sự Khác Biệt

### HS256 (HMAC with SHA-256) - Hiện Tại
```
Secret String: "secret"
┌──────────────────────────────────────┐
│ Sign: Secret + Algorithm             │
│ Verify: Secret (cùng 1 secret)       │
└──────────────────────────────────────┘

Đặc điểm:
❌ Sử dụng cùng 1 secret cho cả sign lẫn verify
❌ Nếu secret bị lộ → bất cứ ai cũng có thể fake token
⚠️ Không an toàn cho hệ thống microservices
```

### RS256 (RSA Signature with SHA-256) - Mới
```
Key Pair: Private Key + Public Key
┌──────────────────────────────────────┐
│ Sign: Private Key (bí mật)           │
│ Verify: Public Key (công khai)       │
└──────────────────────────────────────┘

Đặc điểm:
✅ Private key chỉ server biết (giữ bí mật)
✅ Public key có thể chia sẻ công khai
✅ Chỉ server mới có thể tạo token
✅ Bất cứ ai cũng có thể verify token (nhưng không thể fake)
✅ An toàn cho hệ thống microservices
```

---

## 🔑 Bước 1: Sinh Public & Private Keys

### Cách 1: Sử dụng OpenSSL (Windows)

**Windows 10/11 (có Git Bash):**
```bash
# Mở Git Bash (hoặc PowerShell with OpenSSL)
# Tạo private key
openssl genrsa -out private.key 2048

# Tạo public key từ private key
openssl rsa -in private.key -pubout -out public.key
```

**Hoặc Windows PowerShell:**
```powershell
# Mở PowerShell as Administrator
# Cài OpenSSL nếu chưa có: choco install openssl

openssl genrsa -out private.key 2048
openssl rsa -in private.key -pubout -out public.key
```

### Cách 2: Sử dụng Node.js Script

Hoặc chạy script Node.js để tạo keys:

```javascript
// generateKeys.js
const fs = require('fs');
const crypto = require('crypto');

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

fs.writeFileSync('private.key', privateKey);
fs.writeFileSync('public.key', publicKey);

console.log('✅ Keys generated successfully!');
console.log('Private Key saved to: private.key');
console.log('Public Key saved to: public.key');
```

Chạy:
```bash
node generateKeys.js
```

### Kết Quả

Bạn sẽ nhận 2 file:
- `private.key` - Giữ bí mật (chỉ server biết)
- `public.key` - Có thể chia sẻ công khai

---

## 📁 Bước 2: Tổ Chức Files

```
project/
├── keys/
│   ├── private.key      ← Giữ bí mật
│   ├── public.key       ← Công khai
│   └── .gitignore       ← private.key trong gitignore
├── routes/
│   └── auth.js
├── utils/
│   ├── authHandler.js
│   └── jwtConfig.js     ← File cấu hình JWT mới
└── ...
```

### Tạo .gitignore trong keys folder

```bash
# keys/.gitignore
private.key
*.key
```

---

## ⚙️ Bước 3: Tạo JWT Config Helper

Tạo file `utils/jwtConfig.js`:

```javascript
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

// Cấu hình JWT
const jwtOptions = {
    algorithm: 'RS256',
    expiresIn: '30d'
};

module.exports = {
    privateKey,
    publicKey,
    jwtOptions
};
```

---

## 🔄 Bước 4: Cập Nhật routes/auth.js

**Change từ:**
```javascript
let token = jwt.sign({
    id: getUser._id
}, "secret", {
    expiresIn: '30d'
})
```

**Sang:**
```javascript
const { privateKey, jwtOptions } = require('../utils/jwtConfig');

let token = jwt.sign({
    id: getUser._id
}, privateKey, jwtOptions)
```

---

## 🔐 Bước 5: Cập Nhật utils/authHandler.js

**Change từ:**
```javascript
let result = jwt.verify(token, "secret")
```

**Sang:**
```javascript
const { publicKey } = require('./jwtConfig');

let result = jwt.verify(token, publicKey, { algorithms: ['RS256'] })
```

---

## 📝 Tóm Tắt Các Thay Đổi Code

### File: routes/auth.js
```javascript
var express = require('express');
var router = express.Router();
let userController = require('../controllers/users')
let { RegisterValidator, ChangePasswordValidator, handleResultValidator } = require('../utils/validatorHandler')
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
let { checkLogin } = require('../utils/authHandler')
const { privateKey, jwtOptions } = require('../utils/jwtConfig');  // ← THÊM

/* Login */
router.post('/login', async function (req, res, next) {
    try {
        let { username, password } = req.body;
        let getUser = await userController.FindByUsername(username);

        if (!getUser) {
            res.status(403).send("Tài khoản không tồn tại")
        } else {
            if (getUser.lockTime && getUser.lockTime > Date.now()) {
                res.status(403).send("Tài khoản đang bị ban");
                return;
            }

            if (bcrypt.compareSync(password, getUser.password)) {
                await userController.SuccessLogin(getUser);
                
                // ← THAY ĐỔI: Dùng privateKey và RS256
                let token = jwt.sign({
                    id: getUser._id
                }, privateKey, jwtOptions)
                
                res.send({ token: token, user: getUser })
            } else {
                await userController.FailLogin(getUser);
                res.status(403).send("Thông tin đăng nhập không đúng")
            }
        }
    } catch (error) {
        res.status(500).send({ message: error.message })
    }
});

// ... rest of code
```

### File: utils/authHandler.js
```javascript
let jwt = require('jsonwebtoken')
let userController = require('../controllers/users')
const { publicKey } = require('./jwtConfig')  // ← THÊM

module.exports = {
    checkLogin: async function (req, res, next) {
        let token = req.headers.authorization;
        if (!token || !token.startsWith("Bearer")) {
            res.status(403).send("ban chua dang nhap");
            return;
        }
        token = token.split(" ")[1];
        try {
            // ← THAY ĐỔI: Dùng publicKey và RS256
            let result = jwt.verify(token, publicKey, { 
                algorithms: ['RS256'] 
            })
            let user = await userController.FindById(result.id)
            if (!user) {
                res.status(403).send("ban chua dang nhap");
            } else {
                req.user = user;
                next()
            }
        } catch (error) {
            res.status(403).send("ban chua dang nhap");
        }
    }
}
```

---

## 🚀 Hướng Dẫn Chi Tiết Thực Hiện

### Bước 1: Sinh Keys
```bash
cd C:\NNPTUD\NNPTUD_13032026
node generateKeys.js
```

Hoặc copy script dưới vào file `generateKeys.js` và chạy.

### Bước 2: Tạo keys folder
```bash
mkdir keys
```

### Bước 3: Tạo file jwtConfig.js
Copy code `utils/jwtConfig.js` ở trên.

### Bước 4: Cập nhật routes/auth.js
- Thêm import: `const { privateKey, jwtOptions } = require('../utils/jwtConfig');`
- Thay đổi jwt.sign() từ `"secret"` sang `privateKey, jwtOptions`

### Bước 5: Cập nhật utils/authHandler.js
- Thêm import: `const { publicKey } = require('./jwtConfig')`
- Thay đổi jwt.verify() từ `"secret"` sang `publicKey, { algorithms: ['RS256'] }`

### Bước 6: Restart App
```bash
npm start
```

---

## ✅ Kiểm Tra Nếu Hoạt Động Đúng

### Test 1: Login
```
POST http://localhost:3000/api/v1/auth/login
{
  "username": "testuser123",
  "password": "TestPassword123!"
}
```

Response:
```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": { ... }
}
```

**Lưu ý:** Token sẽ dài hơn (vì dùng RSA)

### Test 2: /me
```
GET http://localhost:3000/api/v1/auth/me
Authorization: Bearer {{token}}
```

Nếu hoạt động → ✅ RS256 thành công!

---

## 🔍 Kiểm Tra Token Trên JWT.io

1. Login để lấy token
2. Vào https://jwt.io
3. Paste token vào phần "Encoded"
4. Xem decoded:
   - Header sẽ có: `"alg": "RS256"`
   - Payload sẽ có: `"id": "user-..."`

---

## 📊 So Sánh HS256 vs RS256

| Tiêu Chí | HS256 | RS256 |
|---------|-------|-------|
| Thuật toán | HMAC | RSA |
| Keys | 1 Secret | Public + Private |
| Sign | Secret | Private Key |
| Verify | Secret | Public Key |
| Bảo mật | Thấp | Cao |
| Microservices | Khó | Tốt |
| Token size | Nhỏ | Lớn |
| Performance | Nhanh | Chậm hơn |

---

## ⚠️ Lưu Ý An Toàn

### ❌ KHÔNG được làm
```
❌ Commit private.key vào git
❌ Share private.key qua email
❌ Lưu private.key trên client
❌ Public key private.key trong code
```

### ✅ NÊN làm
```
✅ Thêm private.key vào .gitignore
✅ Lưu private.key trên server an toàn
✅ Public key có thể chia sẻ
✅ Rotate keys định kỳ
✅ Sử dụng environment variables cho paths
```

---

## 🔄 Quân Trình Hoàn Toàn

```
1. Sinh keys (private.key + public.key)
2. Tạo utils/jwtConfig.js
3. Cập nhật routes/auth.js
4. Cập nhật utils/authHandler.js
5. Restart app
6. Test login + /me
7. Commit changes (trừ private.key!)
```

---

## 💡 Tips Nâng Cao

### Tip 1: Environment Variables
```javascript
// .env
RS256_ALGORITHM=RS256
JWT_EXPIRY=30d
PRIVATE_KEY_PATH=./keys/private.key
PUBLIC_KEY_PATH=./keys/public.key
```

### Tip 2: Key Rotation
- Sinh keys mới định kỳ (6 tháng)
- Giữ keys cũ trong thời gian transition
- Verify với cả keys cũ và mới

### Tip 3: Secure Key Storage
- Production: Sử dụng AWS Secrets Manager, HashiCorp Vault
- Development: Lưu keys local, add vào .gitignore

---

Bắt đầu từ việc sinh keys và tôi sẽ giúp bạn update code! 🚀
