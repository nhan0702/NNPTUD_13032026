# 🎓 Hiểu Về JWT: HS256 vs RS256

## 📚 JWT Là Gì?

JWT (JSON Web Token) là một chuỗi ký tự được sử dụng để:
- ✅ Xác thực người dùng
- ✅ Lưu thông tin (claims)
- ✅ Có chữ ký số (signature) để bảo mật

### Cấu Trúc JWT

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.
eyJpZCI6InVzZXItMDEiLCJpYXQiOjEwLCJleHAiOjIwfQ.
TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ

│                                           │
└───────────────────────────────────────────┘
        Token gồm 3 phần: HEADER.PAYLOAD.SIGNATURE
```

### 3 Phần JWT

**1. HEADER** - Định nghĩa algorithm + type
```json
{
  "alg": "RS256",    // ← Algorithm (RS256 được đề cập)
  "typ": "JWT"       // ← Type là JWT
}
```

**2. PAYLOAD** - Dữ liệu (claims)
```json
{
  "id": "user-001",  // ← Thông tin người dùng
  "iat": 1234567890, // ← Issued at (thời gian tạo)
  "exp": 1234571490  // ← Expiration (thời gian hết hạn)
}
```

**3. SIGNATURE** - Chữ ký số (dùng để bảo mật)
```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret
)
```

---

## 🔐 HS256 (HMAC with SHA-256)

### Cách Hoạt Động

```
┌─────────────────────────────────────────┐
│         HS256 (Symmetric)               │
├─────────────────────────────────────────┤
│                                         │
│  Server                                 │
│  ├─ Secret: "super-secret-string"      │
│  │                                       │
│  ├─ SIGN:                               │
│  │  jwt.sign(data, "super-secret")      │
│  │  → Token tạo ra                      │
│  │                                       │
│  └─ VERIFY:                             │
│     jwt.verify(token, "super-secret")   │
│     → Token hợp lệ?                     │
│                                         │
└─────────────────────────────────────────┘
```

### Ví Dụ Code HS256

**Sign (Tạo Token):**
```javascript
const token = jwt.sign(
  { id: 'user-001' },
  'super-secret-string',  // ← Secret string
  { expiresIn: '30d' }
);
```

**Verify (Kiểm Tra Token):**
```javascript
const decoded = jwt.verify(
  token,
  'super-secret-string'   // ← Cùng secret
);
```

### ❌ Vấn Đề HS256

1. **Secret bị lộ → Token fake**
   ```
   Nếu kẻ xấu biết "super-secret-string"
   → Có thể fake token cho bất cứ user nào
   ```

2. **Không phù hợp Microservices**
   ```
   Service A → Sign token
   Service B → Verify token (cần biết secret)
   Service C → Verify token (cần biết secret)
   → Nhiều service biết secret = nguy hiểm
   ```

3. **Subject (sub) không đủ bảo mật**
   ```
   Token dễ bị modify nếu biết secret
   ```

---

## 🔑 RS256 (RSA Signature with SHA-256)

### Cách Hoạt Động

```
┌──────────────────────────────────────────────────┐
│          RS256 (Asymmetric)                      │
├──────────────────────────────────────────────────┤
│                                                  │
│  Server                                          │
│  ├─ Private Key (BÍ MẬT)                        │
│  │  ├─ SIGN:                                     │
│  │  │  jwt.sign(data, privateKey)                │
│  │  │  → Token ký lên                            │
│  │  │                                             │
│  │  └─ Chỉ server có private key                │
│  │                                                │
│  └─ Public Key (CÔNG KHAI)                      │
│     ├─ VERIFY:                                   │
│     │  jwt.verify(token, publicKey)              │
│     │  → Ai cũng có thể verify                   │
│     │                                             │
│     └─ Tất cả service có thể dùng                │
│                                                  │
└──────────────────────────────────────────────────┘
```

### Ví Dụ Code RS256

**Sign (Tạo Token):**
```javascript
const { privateKey } = require('./jwtConfig');

const token = jwt.sign(
  { id: 'user-001' },
  privateKey,        // ← Private key (bí mật)
  { algorithm: 'RS256', expiresIn: '30d' }
);
```

**Verify (Kiểm Tra Token):**
```javascript
const { publicKey } = require('./jwtConfig');

const decoded = jwt.verify(
  token,
  publicKey,         // ← Public key (công khai)
  { algorithms: ['RS256'] }
);
```

### ✅ Lợi Ích RS256

1. **Private Key không lộ → Token an toàn**
   ```
   Nếu kẻ xấu biết publicKey
   → Cũng không thể fake token
   → Vì chỉ server có private key
   ```

2. **Phù hợp Microservices**
   ```
   Service A → Sign token (private key)
   Service B → Verify (public key)
   Service C → Verify (public key)
   Service D → Verify (public key)
   → Các service khác không cần biết private key
   ```

3. **Non-Repudiation**
   ```
   Server không thể phủ nhận đã tạo token
   vì chỉ server có private key
   ```

---

## 📊 So Sánh Chi Tiết

### Độ An Toàn

```
HS256:
┌─────────────────────────────┐
│ Nếu secret bị lộ            │
│ → Bất cứ ai cũng fake token │
│ → CÓ NGUY HIỂM             │
└─────────────────────────────┘

RS256:
┌──────────────────────────────┐
│ Nếu public key bị lộ         │
│ → Chỉ có thể verify token    │
│ → KHÔNG THỂ fake token       │
│ → AN TOÀN                    │
└──────────────────────────────┘
```

### Kích Thước Token

```
HS256:
"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." (ngắn hơn)

RS256:
"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." (dài hơn)
Vì RSA key lớn hơn HMAC secret
```

### Hiệu Suất

```
HS256:
┌──────────────────┐
│ Nhanh hơn       │
│ Tính toán đơn   │
└──────────────────┘

RS256:
┌──────────────────┐
│ Chậm hơn        │
│ RSA phức tạp    │
└──────────────────┘

Nhưng sự chậm là có thể chấp nhận
vì sự an toàn quan trọng hơn
```

---

## 📈 Use Cases

### Dùng HS256 Khi:
- ✅ Hệ thống **một server** (monolithic)
- ✅ Secret được giữ **rất an toàn**
- ✅ Yêu cầu **performance cao** (không critical)
- ✅ **Học tập/Development**

### Dùng RS256 Khi:
- ✅ **Microservices** (nhiều service)
- ✅ **OAuth 2.0 providers**
- ✅ **Production** (bảo mật cao)
- ✅ Public API (token cần share)
- ✅ **Enterprise** (yêu cầu bảo mật)

---

## 🔀 Chuyển HS256 → RS256

### Các Bước Chính:

1. **Sinh RSA key pair**
   ```bash
   node generateKeys.js
   ```

2. **Update sign (private key)**
   ```javascript
   jwt.sign(data, privateKey, { algorithm: 'RS256' })
   ```

3. **Update verify (public key)**
   ```javascript
   jwt.verify(token, publicKey, { algorithms: ['RS256'] })
   ```

4. **Restart service**
   ```bash
   npm start
   ```

### Backward Compatibility

**⚠️ Lưu ý:** Token tạo bằng HS256 sẽ không thể verify bằng RS256!

**Giải pháp:**
- Logout hết users (xóa token)
- Hoặc hỗ trợ cả HS256 + RS256 tạm thời

---

## 🎯 Project Của Bạn

**Trước (HS256):**
```javascript
jwt.sign(data, "secret", { expiresIn: '30d' })
jwt.verify(token, "secret")
```

**Sau (RS256):**
```javascript
jwt.sign(data, privateKey, { algorithm: 'RS256', expiresIn: '30d' })
jwt.verify(token, publicKey, { algorithms: ['RS256'] })
```

---

## 🚀 Tóm Tắt

| Điểm | HS256 | RS256 |
|-----|-------|-------|
| Secret/Key | 1 secret | Public + Private |
| An toàn | Thấp | Cao |
| Microservices | Khó | Tốt |
| Performance | Nhanh | Bình thường |
| Use case | Dev/Learning | Production |

**RS256 là lựa chọn tốt hơn cho production!** ✅

---

## 📚 Tài Liệu Tham Khảo

- JWT Official: https://jwt.io
- OpenID Connect (dùng RS256): https://openid.net
- OAuth 2.0 (dùng RS256): https://oauth.net/2/
- Node.js jsonwebtoken: https://github.com/auth0/node-jsonwebtoken

---

**Giờ bạn đã hiểu RS256! Hãy implements nó! 🎉**
