var express = require("express");
var router = express.Router();
let roleManager = require("../schemas/roles");

router.get("/", async function (req, res, next) {
    try {
        let roles = roleManager.findAll();
        res.send(roles);
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
});

router.get("/:id", async function (req, res, next) {
    try {
        let result = roleManager.findById(req.params.id);
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

router.post("/", async function (req, res, next) {
    try {
        let newItem = roleManager.create(
            req.body.name,
            req.body.description || ''
        );
        res.send(newItem);
    } catch (err) {
        res.status(400).send({ message: err.message });
    }
});

router.put("/:id", async function (req, res, next) {
    try {
        let id = req.params.id;
        let updatedItem = roleManager.update(id, req.body);
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
        let updatedItem = roleManager.delete(id);
        if (!updatedItem) {
            return res.status(404).send({ message: "id not found" });
        }
        res.send(updatedItem);
    } catch (err) {
        res.status(400).send({ message: err.message });
    }
});

module.exports = router;