let userModel = require('../schemas/users')
module.exports = {
    CreateAnUser: async function (username, password, email, role,
        fullName, avatarUrl, status, loginCount) {
        let newItem = new userModel({
            username: username,
            password: password,
            email: email,
            fullName: fullName,
            avatarUrl: avatarUrl,
            status: status,
            role: role,
            loginCount: loginCount
        });
        await newItem.save();
        return newItem;
    },
    GetAnUserByUsername: async function (username) {
        return await userModel.findOne({
            isDeleted: false,
            username: username
        })
    }, GetAnUserById: async function (id) {
        return await userModel.findOne({
            isDeleted: false,
            _id: id
        })
    },
    ChangePassword: async function (userId, newPassword) {
        let user = await userModel.findById(userId);
        if (!user) {
            throw new Error("User not found");
        }
        user.password = newPassword;
        await user.save();
        return user;
    }
}