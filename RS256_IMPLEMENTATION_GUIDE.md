# 🚀 Hướng Dẫn Thực Hiện RS256 - Step by Step

## 📋 Checklist Toàn Bộ

- [ ] Bước 1: Chạy script sinh keys
- [ ] Bước 2: Xác minh keys được tạo
- [ ] Bước 3: Kiểm tra files đã được cập nhật
- [ ] Bước 4: Restart app
- [ ] Bước 5: Test login + /me
- [ ] Bước 6: Verify token format

---

## 🔧 Bước 1: Sinh RSA Keys

### 1.1 Chạy Script
Mở PowerShell/Terminal tại thư mục project:

```bash
cd C:\NNPTUD\NNPTUD_13032026
node generateKeys.js
```

### 1.2 Output Kỳ Vọng
```
🔐 Generating RSA 2048 key pair...
✅ Created keys folder
✅ Private key saved to: keys/private.key
✅ Public key saved to: keys/public.key

📋 Next steps:
1. Create utils/jwtConfig.js
2. Update routes/auth.js to use privateKey
3. Update utils/authHandler.js to use publicKey
4. Restart app: npm start

⚠️  IMPORTANT: Add keys/private.key to .gitignore!
```

### 1.3 Kiểm Tra Files
```bash
# Kiểm tra keys folder
ls -la keys/

# Output:
# -rw-r--r-- private.key
# -rw-r--r-- public.key
# -rw-r--r-- README.md
# -rw-r--r-- .gitignore
```

---

## ✅ Bước 2: Xác Minh Files Đã Được Tạo

### Danh Sách Files Cần Có:

```
✅ keys/
   ├── private.key        ← Được sinh
   ├── public.key         ← Được sinh
   ├── README.md          ← Đã tạo
   └── .gitignore         ← Đã tạo

✅ utils/
   ├── jwtConfig.js       ← Đã tạo
   └── authHandler.js     ← Đã cập nhật

✅ routes/
   └── auth.js            ← Đã cập nhật

✅ generateKeys.js        ← Đã tạo
```

### Kiểm Tra Content Files Quan Trọng

**utils/jwtConfig.js phải chứa:**
```javascript
const { publicKey } = require('./jwtConfig')
const jwtOptions = {
    algorithm: 'RS256',
    expiresIn: '30d'
};
```

**routes/auth.js phải chứa:**
```javascript
const { privateKey, jwtOptions } = require('../utils/jwtConfig');
// ...
let token = jwt.sign({
    id: getUser._id
}, privateKey, jwtOptions)
```

**utils/authHandler.js phải chứa:**
```javascript
const { publicKey } = require('./jwtConfig')
let result = jwt.verify(token, publicKey, { algorithms: ['RS256'] })
```

---

## 🔄 Bước 3: Cập Nhật .gitignore Chính (Project Root)

Mở file `.gitignore` ở root project và thêm:

```
# JWT Keys - NEVER commit private.key!
keys/private.key
keys/*.key
```

---

## ♻️ Bước 4: Restart App

### 4.1 Dừng App Cũ
Nhấn `Ctrl + C` trong terminal đang chạy `npm start`

### 4.2 Xóa Cache (Tùy Chọn)
```bash
rm -r node_modules/.cache
```

### 4.3 Khởi Động App Lại
```bash
npm start
```

### 4.4 Output Kỳ Vọng
```
Using local JSON file storage for data
[nodemon] restarting due to changes...
[nodemon] starting `node ./bin/www`
✅ Server running on port 3000
```

---

## 🧪 Bước 5: Test Login

### 5.1 Login Request (Postman)

```
POST http://localhost:3000/api/v1/auth/login

Headers:
Content-Type: application/json

Body:
{
  "username": "testuser123",
  "password": "TestPassword123!"
}
```

### 5.2 Response Kỳ Vọng

```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6InVzZXItLWFkbWluLWZpcnN0LXdpdGg4NGNoYXJzLWZpbGxlZC1hcnJheToo...",
  "user": {
    "_id": "...",
    "username": "testuser123",
    "email": "...",
    ...
  }
}
```

**Lưu ý:** Token sẽ dài hơn vì RS256 sử dụng RSA encryption

### 5.3 Copy Token
Sao chép giá trị `token` từ response

---

## 🔐 Bước 6: Test /me Endpoint

### 6.1 Request /me

```
GET http://localhost:3000/api/v1/auth/me

Headers:
Content-Type: application/json
Authorization: Bearer {{token}}
```

### 6.2 Response Kỳ Vọng

```json
{
  "_id": "...",
  "username": "testuser123",
  "email": "...",
  "role": {
    "_id": "...",
    "name": "user",
    ...
  },
  ...
}
```

---

## 🔍 Bước 7: Verify Token Format

### 7.1 Kiểm Tra Algorithm

1. Vào https://jwt.io
2. Paste token vào phần "Encoded"
3. Xem phần "HEADER.PAYLOAD.SIGNATURE"

### 7.2 Header Kỳ Vọng

Phần Header phải là:
```json
{
  "alg": "RS256",
  "typ": "JWT"
}
```

### 7.3 Payload Kỳ Vọng

Phần Payload phải chứa:
```json
{
  "id": "user-...",
  "iat": 1678900000,
  "exp": 1681492000
}
```

### 7.4 Signature

Signature hợp lệ vì:
- ✅ Signed bằng private.key
- ✅ Public key có thể verify

---

## ✨ Verify Thành Công!

Nếu bạn:
1. ✅ Chạy generateKeys.js thành công
2. ✅ Login nhận token RS256
3. ✅ /me endpoint hoạt động
4. ✅ JWT.io hiển thị `alg: RS256`

→ **Chúc mừng! Đã chuyển sang RS256 thành công!** 🎉

---

## 🐛 Troubleshooting

### ❌ Error: "Cannot find module 'jwtConfig'"

**Giải pháp:**
1. Kiểm tra file `utils/jwtConfig.js` tồn tại
2. Kiểm tra import đúng: `require('../utils/jwtConfig')`
3. Restart app

### ❌ Error: "ENOENT: no such file or directory 'keys/private.key'"

**Giải pháp:**
```bash
# Chạy lại script sinh keys
node generateKeys.js
```

### ❌ Error: "JsonWebTokenError: invalid signature"

**Giải pháp:**
1. Token có thể bị lỗi
2. Login lại để lấy token mới
3. Kiểm tra keys/private.key và keys/public.key match nhau

### ❌ Token Failed Verify (/me returns 403)

**Giải pháp:**
1. Kiểm tra Authorization header: `Bearer {{token}}`
2. Kiểm tra token không hết hạn
3. Kiểm tra public.key đúng

---

## 📊 Comparison: HS256 vs RS256 (Project Của Bạn)

| Tiêu Chí | HS256 (Cũ) | RS256 (Mới) |
|---------|-----------|-----------|
| Secret | "secret" string | private.key file |
| Sign | jwt.sign(data, "secret") | jwt.sign(data, privateKey) |
| Verify | jwt.verify(token, "secret") | jwt.verify(token, publicKey) |
| Bảo mật | ⚠️ Thấp | ✅ Cao |
| Key file | Không | ✅ 2 files |

---

## 🎯 Kết Luận

**Lợi ích của RS256:**

1. ✅ **Bảo mật cao hơn** - Private key giữ bí mật
2. ✅ **Microservices** - Public key có thể chia sẻ
3. ✅ **Non-repudiation** - Server không thể phủ nhận đã tạo token
4. ✅ **Industry standard** - OAuth 2.0, OpenID Connect sử dụng RS256

**Hãy hoàn tất 7 bước trên để có RS256 đầy đủ!** 🚀
