# ⚡ RS256 Quick Start

## 🔑 Sinh Keys (1 lệnh)
```bash
node generateKeys.js
```

## ✅ Files Đã Được Cảnh Báo

✓ `utils/jwtConfig.js` - Config RS256  
✓ `routes/auth.js` - Updated login endpoint  
✓ `utils/authHandler.js` - Updated verify logic  
✓ `keys/` folder - Private/Public keys  
✓ `generateKeys.js` - Script sinh keys  

---

## 🚀 Áp Dụng (3 Bước)

### 1. Sinh Keys
```bash
node generateKeys.js
```

### 2. Restart App
```bash
npm start
```

### 3. Test
```
POST /api/v1/auth/login
  → Nhận token RS256

GET /api/v1/auth/me + token
  → ✅ Hoạt động
```

---

## 🔍 Verify Success

Login → Copy token → Paste vào https://jwt.io

Header sẽ hiển thị:
```json
{
  "alg": "RS256",  ← ✅ Đây là chứng minh
  "typ": "JWT"
}
```

---

## ⚠️ Important

```
❌ NEVER commit keys/private.key
✅ keys/private.key in .gitignore
✅ public.key safe to share
```

---

**Chạy `node generateKeys.js` để bắt đầu!** 🎉
