var express = require('express');
var router = express.Router();
let userController = require('../controllers/users')
let { RegisterValidator, ChangePasswordValidator, handleResultValidator } = require('../utils/validatorHandler')
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
let { checkLogin } = require('../utils/authHandler')
const { privateKey, jwtOptions } = require('../utils/jwtConfig')

/* Register */
router.post('/register', RegisterValidator, handleResultValidator, async function (req, res, next) {
    try {
        // Create a default role if needed
        let { RoleManager } = require('../utils/dbLocal');
        let defaultRole = RoleManager.findByName('user');
        let roleId = defaultRole ? defaultRole._id : null;

        if (!roleId) {
            defaultRole = RoleManager.create('user', 'Default user role');
            roleId = defaultRole._id;
        }

        let newUser = userController.CreateAnUser(
            req.body.username,
            req.body.password,
            req.body.email,
            roleId,
            req.body.fullName || '',
            req.body.avatarUrl || null,
            false,
            0
        );
        res.send({
            message: "Đăng ký thành công"
        })
    } catch (error) {
        res.status(400).send({ message: error.message })
    }
});

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

/* Get current user */
router.get('/me', checkLogin, function (req, res, next) {
    res.send(req.user)
})

/* Change password */
router.post('/changepassword', checkLogin, ChangePasswordValidator, handleResultValidator, async function (req, res, next) {
    try {
        let userId = req.user._id;
        let { oldPassword, newPassword } = req.body;

        let updatedUser = await userController.ChangePassword(userId, oldPassword, newPassword);

        // Không trả về password trong response
        res.send({
            message: "Thay đổi mật khẩu thành công",
            user: {
                _id: updatedUser._id,
                username: updatedUser.username,
                email: updatedUser.email,
                fullName: updatedUser.fullName,
                avatarUrl: updatedUser.avatarUrl,
                status: updatedUser.status,
                role: updatedUser.role
            }
        });
    } catch (error) {
        res.status(400).send({ message: error.message });
    }
})

module.exports = router;
