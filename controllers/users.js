let userManager = require('../schemas/users');
let bcrypt = require('bcrypt');
let { RoleManager } = require('../utils/dbLocal');

module.exports = {
    CreateAnUser: function (username, password, email, role, fullname, avatar, status, logincount) {
        // Hash password before creating
        let salt = bcrypt.genSaltSync(10);
        let hashedPassword = bcrypt.hashSync(password, salt);

        return userManager.create(
            username,
            hashedPassword,
            email,
            fullname,
            avatar,
            status,
            role
        );
    },

    FindByUsername: async function (username) {
        return userManager.findByUsername(username);
    },

    FailLogin: async function (user) {
        user.loginCount++;
        if (user.loginCount == 3) {
            user.loginCount = 0;
            user.lockTime = new Date(Date.now() + 60 * 60 * 1000);
        }
        userManager.update(user._id, {
            loginCount: user.loginCount,
            lockTime: user.lockTime
        });
    },

    SuccessLogin: async function (user) {
        userManager.update(user._id, { loginCount: 0 });
    },

    GetAllUser: async function () {
        let users = userManager.findAll();
        return users.map(user => ({
            ...user,
            role: RoleManager.findById(user.role)
        }));
    },

    FindById: async function (id) {
        try {
            let getUser = userManager.findById(id);
            if (getUser) {
                return {
                    ...getUser,
                    role: RoleManager.findById(getUser.role)
                };
            }
            return null;
        } catch (error) {
            return false
        }
    },

    ChangePassword: async function (userId, oldPassword, newPassword) {
        try {
            // Lấy user từ database
            let user = userManager.findById(userId);
            if (!user) {
                throw new Error("Người dùng không tồn tại");
            }

            // Kiểm tra mật khẩu cũ
            if (!bcrypt.compareSync(oldPassword, user.password)) {
                throw new Error("Mật khẩu cũ không đúng");
            }

            // Hash mật khẩu mới
            let salt = bcrypt.genSaltSync(10);
            let hashedNewPassword = bcrypt.hashSync(newPassword, salt);

            // Cập nhật mật khẩu
            let updatedUser = userManager.update(userId, {
                password: hashedNewPassword
            });

            return updatedUser;
        } catch (error) {
            throw error;
        }
    }
}