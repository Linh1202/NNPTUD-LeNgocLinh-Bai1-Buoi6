let userController = require('../controllers/users')
let jwt = require('jsonwebtoken')
let fs = require('fs');
let path = require('path');

// Đọc public key
const publicKey = fs.readFileSync(path.join(__dirname, '../publicKey.pem'), 'utf8')

module.exports = {
    CheckLogin: async function (req, res, next) {
        try {
            let token = req.headers.authorization;
            if (!token) {
                res.status(404).send({
                    message: "ban chua dang nhap"
                })
                return;
            }
            // Sử dụng RS256 với public key để verify
            let result = jwt.verify(token, publicKey, { algorithm: 'RS256' })
            if (result.exp * 1000 < Date.now()) {
                res.status(404).send({
                    message: "ban chua dang nhap"
                })
                return;
            }
            let user = await userController.GetAnUserById(result.id);
            if (!user) {
                res.status(404).send({
                    message: "ban chua dang nhap"
                })
                return;
            }
            req.user = user;
            next()
        } catch (error) {
            res.status(404).send({
                message: "ban chua dang nhap"
            })
        }
    }
}