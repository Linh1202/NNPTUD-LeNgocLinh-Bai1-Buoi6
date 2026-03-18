let express = require('express');
let router = express.Router()
let userController = require('../controllers/users')
let bcrypt = require('bcrypt');
const { CheckLogin } = require('../utils/authHandler');
let jwt = require('jsonwebtoken')
const { ChangePasswordValidator, validatedResult } = require('../utils/validator')
let fs = require('fs');
let path = require('path');

// Đọc private key
const privateKey = fs.readFileSync(path.join(__dirname, '../privateKey.pem'), 'utf8')
router.post('/register', async function (req, res, next) {
    try {
        let { username, password, email } = req.body;
        let newUser = await userController.CreateAnUser(username, password, email,
            "69b1265c33c5468d1c85aad8"
        )
        res.send(newUser)
    } catch (error) {
        res.status(404).send({
            message: error.message
        })
    }
})

router.post('/login', async function (req, res, next) {
    try {
        let { username, password } = req.body;
        let user = await userController.GetAnUserByUsername(username);
        if (!user) {
            res.status(404).send({
                message: "thong tin dang nhap khong dung"
            })
            return;
        }
        if (user.lockTime > Date.now()) {
            res.status(404).send({
                message: "ban dang bi ban"
            })
            return;
        }
        if (bcrypt.compareSync(password, user.password)) {
            user.loginCount = 0;
            await user.save()
            // Sử dụng RS256 (RSA) với private key
            let token = jwt.sign({
                id: user._id
            }, privateKey, {
                algorithm: 'RS256',
                expiresIn: '1d'
            })
            res.send(token)
        } else {
            user.loginCount++;
            if (user.loginCount == 3) {
                user.loginCount = 0;
                user.lockTime = Date.now() + 3600 * 1000;
            }
            await user.save()
            res.status(404).send({
                message: "thong tin dang nhap khong dung"
            })
        }
    } catch (error) {
        res.status(404).send({
            message: error.message
        })
    }
})
router.get('/me', CheckLogin, function (req, res, next) {
    res.send(req.user)
})

router.post('/changepassword', CheckLogin, ChangePasswordValidator, validatedResult, async function (req, res, next) {
    try {
        let { oldpassword, newpassword } = req.body;
        let user = req.user;
        
        // Kiểm tra mật khẩu cũ có đúng không
        if (!bcrypt.compareSync(oldpassword, user.password)) {
            res.status(404).send({
                message: "mat khau cu khong dung"
            })
            return;
        }
        
        // Kiểm tra mật khẩu mới không được giống mật khẩu cũ
        if (bcrypt.compareSync(newpassword, user.password)) {
            res.status(404).send({
                message: "mat khau moi khong duoc giong mat khau cu"
            })
            return;
        }
        
        // Cập nhật mật khẩu mới
        let updatedUser = await userController.ChangePassword(user._id, newpassword);
        res.send({
            message: "doi mat khau thanh cong",
            user: updatedUser
        })
    } catch (error) {
        res.status(404).send({
            message: error.message
        })
    }
})

module.exports = router