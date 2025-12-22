// src/middlewares/authMiddleware.js
const jwt = require("jsonwebtoken");
require("dotenv").config();

const verifyAccessToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "No token" });
  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token" });

  jwt.verify(token, process.env.JWT_ACCESS_SECRET, (err, payload) => {
    if (err) return res.status(401).json({ message: "Invalid token" });
    req.user = payload; // { userId, username, roles, iat, exp }
    next();
  });
};

module.exports = {
  verifyAccessToken,
};
