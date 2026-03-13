# 🔐 Hướng Dẫn Test Changepassword Trên Postman

## 📋 Tổng Quan

Endpoint `/changepassword` cho phép người dùng đã đăng nhập thay đổi mật khẩu.

**Yêu cầu:**
- ✅ Phải đăng nhập (cần token)
- ✅ Cần 2 trường: `oldPassword` và `newPassword`
- ✅ `newPassword` phải mạnh (validate giống register)

---

## 📝 Các Bước Thực Hiện

### Bước 1: Login để lấy Token
Nếu chưa có token, hãy login trước:

```
POST http://localhost:3000/api/v1/auth/login

Headers:
Content-Type: application/json

Body (JSON):
{
  "username": "testuser123",
  "password": "TestPassword123!"
}
```

Response sẽ chứa token:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": { ... }
}
```

---

### Bước 2: Tạo Request Change Password

#### 2.1 Cấu Hình Request
- **Method**: `POST`
- **URL**: `http://localhost:3000/api/v1/auth/changepassword`

#### 2.2 Thêm Headers
Chọn tab "Headers" và thêm:

```
Content-Type: application/json
Authorization: Bearer {{token}}
```

**Hoặc sử dụng token manual:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### 2.3 Thêm Body (JSON)

Chọn tab "Body" → "raw" → "JSON"

```json
{
  "oldPassword": "TestPassword123!",
  "newPassword": "NewPassword456!"
}
```

**Yêu cầu mật khẩu mới:**
- ✓ Tối thiểu 8 ký tự
- ✓ Ít nhất 1 chữ hoa (A-Z)
- ✓ Ít nhất 1 chữ thường (a-z)
- ✓ Ít nhất 1 số (0-9)
- ✓ Ít nhất 1 ký tự đặc biệt (!@#$%^&*)

#### 2.4 Nhấn "Send"

---

## ✅ Response Thành Công

Nếu thành công, sẽ nhận response:

```json
{
  "message": "Thay đổi mật khẩu thành công",
  "user": {
    "_id": "user-abc123",
    "username": "testuser123",
    "email": "testuser@example.com",
    "fullName": "",
    "avatarUrl": "https://i.sstatic.net/l60Hf.png",
    "status": false,
    "role": "role-user-001"
  }
}
```

**Lưu ý:** Không trả về password trong response (vì bảo mật)

---

## ❌ Các Lỗi Thường Gặp

### 1. "ban chua dang nhap" (403)
**Nguyên nhân**: Token chưa được gửi hoặc token không hợp lệ

**Giải pháp**:
- Kiểm tra Authorization header
- Đảm bảo format: `Bearer {{token}}`
- Login lại để lấy token mới

### 2. "Mật khẩu cũ không đúng"
**Nguyên nhân**: `oldPassword` sai

**Giải pháp**:
- Kiểm tra `oldPassword` có đúng không
- Lưu ý chữ hoa/thường
- Nếu quên, hãy reset password (ngoài phạm vi hệ thống hiện tại)

### 3. "Mật khẩu mới không được rỗng"
**Nguyên nhân**: Thiếu `newPassword`

**Giải pháp**:
- Kiểm tra body JSON có `newPassword` không
- Đảm bảo không để trống

### 4. "Mat khau moi dai it nhat 8 ki tu..."
**Nguyên nhân**: Mật khẩu mới không đủ mạnh

**Giải pháp**:
- Sử dụng mật khẩu mạnh: `NewPassword456!`
- Phải chứa:
  - ✓ Ít nhất 8 ký tự
  - ✓ Ít nhất 1 chữ hoa
  - ✓ Ít nhất 1 chữ thường
  - ✓ Ít nhất 1 số
  - ✓ Ít nhất 1 ký tự đặc biệt

### 5. "Người dùng không tồn tại"
**Nguyên nhân**: User ID không hợp lệ (hiếm khi xảy ra)

**Giải pháp**:
- Login lại
- Restart app

---

## 📝 Mẫu Request (Copy & Paste)

### ✅ Request Thành Công
```
POST http://localhost:3000/api/v1/auth/changepassword

Headers:
Content-Type: application/json
Authorization: Bearer {{token}}

Body:
{
  "oldPassword": "TestPassword123!",
  "newPassword": "NewPassword456!"
}
```

### ❌ Request Sai (Mật khẩu yếu)
```
{
  "oldPassword": "TestPassword123!",
  "newPassword": "weak"  // ❌ Quá yếu
}
```

### ❌ Request Sai (Sai mật khẩu cũ)
```
{
  "oldPassword": "WrongPassword123!",  // ❌ Sai
  "newPassword": "NewPassword456!"
}
```

---

## 🔄 Quy Trình Đầy Đủ

```
1. Login → Lấy token ✅
2. Tạo request POST /changepassword ✅
3. Settings headers + body ✅
4. Send request ✅
5. Check response ✅
```

---

## 💡 Tips

### Tip 1: Tự động lưu token sau login
Thêm script trong tab "Tests" của login request:
```javascript
if (pm.response.code === 200) {
    var jsonData = pm.response.json();
    pm.environment.set("token", jsonData.token);
}
```

### Tip 2: Test mật khẩu mạnh
Dùng các mật khẩu mạnh để test:
- ✅ `TestPassword123!`
- ✅ `SecurePass456@`
- ✅ `MyNewPass789#`
- ❌ `weak`
- ❌ `12345678`
- ❌ `password`

### Tip 3: Lưu password mới
Sau khi đổi password, ghi chép password mới để login lần sau

```
Username: testuser123
Old Password: TestPassword123! ← Không còn dùng được
New Password: NewPassword456!  ← Dùng cái này login lần sau
```

### Tip 4: Test lại với password mới
Sau khi change password thành công, hãy:
1. Tạo request login mới
2. Dùng username + `newPassword`
3. Kiểm tra có login được không

```
POST /api/v1/auth/login
{
  "username": "testuser123",
  "password": "NewPassword456!"  // ← Password mới
}
```

---

## 📊 Checklist

- [ ] Đã login được
- [ ] Có token từ login
- [ ] Authorization header đúng: `Bearer {{token}}`
- [ ] oldPassword đúng
- [ ] newPassword mạnh (8+ ký tự, có chữ hoa, số, ký tự đặc biệt)
- [ ] Method là POST
- [ ] URL đúng: `/api/v1/auth/changepassword`
- [ ] Nhận response thành công
- [ ] Test login với password mới

---

## 🎯 Hoàn Tất

Nếu bạn:
1. ✅ Change password thành công
2. ✅ Có thể login với password mới
3. ✅ /me endpoint hoạt động

→ **Chúc mừng! Chức năng change password đã hoạt động đúng!** 🎉
