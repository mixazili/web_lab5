// src/middlewares/rateLimiter.js
const rateLimit = require("express-rate-limit");
const ms = require("ms");
require("dotenv").config();

const windowMs = parseInt(process.env.RATE_LIMIT_WINDOW_MS || "5000"); // ms
const max = parseInt(process.env.RATE_LIMIT_MAX || "10");

const authLimiter = rateLimit({
  windowMs,
  max,
  message: { error: "Too many requests, try later" },
  standardHeaders: true,
  legacyHeaders: false,
});

module.exports = authLimiter;
