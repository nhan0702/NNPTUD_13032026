var express = require("express");
var router = express.Router();
let { checkLogin } = require('../utils/authHandler')
let { userCreateValidator
    , userUpdateValidator
    , handleResultValidator } = require('../utils/validatorHandler')
let userController = require("../controllers/users");
let userManager = require("../schemas/users");
let bcrypt = require('bcrypt');

router.get("/", checkLogin, async function (req, res, next) {
    try {
        let users = await userController.GetAllUser();
        res.send(users);
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
});

router.get("/:id", async function (req, res, next) {
    try {
        let result = await userController.FindById(req.params.id);
        if (result) {
            res.send(result);
        }
        else {
            res.status(404).send({ message: "id not found" });
        }
    } catch (error) {
        res.status(404).send({ message: "id not found" });
    }
});

router.post("/", userCreateValidator, handleResultValidator,
    async function (req, res, next) {
        try {
            let newItem = userController.CreateAnUser(
                req.body.username,
                req.body.password,
                req.body.email,
                req.body.role,
                req.body.fullName || '',
                req.body.avatarUrl || null,
                req.body.status || false,
                0
            )
            res.send(newItem);
        } catch (err) {
            res.status(400).send({ message: err.message });
        }
    });

router.put("/:id", userUpdateValidator, handleResultValidator, async function (req, res, next) {
    try {
        let id = req.params.id;

        // Handle password hashing if password is being updated
        let updateData = { ...req.body };
        if (updateData.password) {
            let salt = bcrypt.genSaltSync(10);
            updateData.password = bcrypt.hashSync(updateData.password, salt);
        }

        let updatedItem = userManager.update(id, updateData);
        if (!updatedItem) {
            return res.status(404).send({ message: "id not found" });
        }

        res.send(updatedItem);
    } catch (err) {
        res.status(400).send({ message: err.message });
    }
});

router.delete("/:id", async function (req, res, next) {
    try {
        let id = req.params.id;
        let updatedItem = userManager.delete(id);
        if (!updatedItem) {
            return res.status(404).send({ message: "id not found" });
        }
        res.send(updatedItem);
    } catch (err) {
        res.status(400).send({ message: err.message });
    }
});

module.exports = router;