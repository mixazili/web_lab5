// src/routes/auth.routes.js
const express = require("express");
const router = express.Router();
const authController = require("../controllers/authController");
const authLimiter = require("../middlewares/rateLimiter");

router.post("/register", authLimiter, authController.register);
router.post("/login", authLimiter, authController.login);
router.post("/refresh", authLimiter, authController.refresh);
router.post("/logout", authLimiter, authController.logout);

module.exports = router;
