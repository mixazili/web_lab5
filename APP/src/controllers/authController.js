// src/controllers/authController.js
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const User = require("../models/User");
const logger = require("../config/logger");
const {
  authSuccess,
  authFailure,
  refreshCount,
  suspiciousCount,
  activeRefreshTokens,
} = require("../config/monitor");

require("dotenv").config();

function signAccessToken(payload) {
  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET, {
    expiresIn: process.env.ACCESS_TOKEN_EXP || "15m",
  });
}
function signRefreshToken(payload) {
  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.REFRESH_TOKEN_EXP || "7d",
  });
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

async function register(req, res) {
  const { username, password } = req.body;
  try {
    const exists = await User.findOne({ username });
    if (exists) {
      logger.info("register_failed", { username, reason: "exists" });
      return res.status(400).json({ message: "User exists" });
    }
    const user = new User({ username });
    await user.setPassword(password);
    await user.save();

    logger.info("register_success", { username });
    authSuccess.inc();

    res.status(201).json({ message: "Registered" });
  } catch (err) {
    logger.error("register_error", { err: err.message });
    res.status(500).json({ message: "Server error" });
  }
}

async function login(req, res) {
  const { username, password, deviceInfo } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) {
      logger.info("login_fail_no_user", { username });
      authFailure.inc();
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const ok = await user.validatePassword(password);
    if (!ok) {
      user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
      user.lastFailedAt = new Date();
      await user.save();
      logger.info("login_failed", {
        username,
        attempts: user.failedLoginAttempts,
      });
      authFailure.inc();

      // если больше порога -> помечаем подозрительное
      if (user.failedLoginAttempts >= 5) {
        logger.warn("suspicious_multiple_failed_logins", {
          username,
          attempts: user.failedLoginAttempts,
        });
        suspiciousCount.inc();
        // можно отправлять уведомление оператору тут
      }
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // успешный вход - сбрасываем счётчик
    user.failedLoginAttempts = 0;
    user.lastFailedAt = null;

    // создаём токены
    const payload = {
      userId: user._id,
      username: user.username,
      roles: user.roles,
    };
    const accessToken = signAccessToken(payload);
    const refreshToken = signRefreshToken({
      userId: user._id,
      tokenId: crypto.randomUUID(),
    });

    // храним хэш refresh token
    const tokenHash = hashToken(refreshToken);
    user.refreshTokens.push({
      tokenHash,
      deviceInfo: deviceInfo || req.get("user-agent"),
    });
    await user.save();

    // обновляем метрики
    authSuccess.inc();
    activeRefreshTokens.inc();

    logger.info("login_success", { username, deviceInfo });
    // возвращаем refresh в httpOnly cookie и access в body
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.COOKIE_SECURE === "true",
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7,
      path: "/", // ← ЭТО ВАЖНО
    });
    res.json({ accessToken });
  } catch (err) {
    logger.error("login_error", { err: err.message });
    res.status(500).json({ message: "Server error" });
  }
}

async function refresh(req, res) {
  // console.log('=== DEBUG COOKIES REFRESH ===');
  // console.log('1. req.cookies:', req.cookies); // должен быть объект
  // console.log('2. req.cookies?.refreshToken:', req.cookies?.refreshToken);
  // console.log('3. req.headers.cookie:', req.headers.cookie); // raw строка
  // console.log('=====================');
  const token = req.cookies?.refreshToken || req.body?.refreshToken;
  if (!token) return res.status(401).json({ message: "No refresh token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    const userId = decoded.userId;
    const tokenHash = hashToken(token);

    const user = await User.findById(userId);
    if (!user) {
      logger.info("refresh_fail_no_user", { userId });
      authFailure.inc();
      return res.status(401).json({ message: "Invalid refresh" });
    }

    // Найдём сохранённый хэш
    const stored = user.refreshTokens.find((rt) => rt.tokenHash === tokenHash);

    if (!stored) {
      // возможный reuse/краже: refresh-token не найден — подозрительное событие
      logger.warn("refresh_reuse_or_invalid", {
        userId,
        username: user.username,
      });
      suspiciousCount.inc();
      authFailure.inc();
      // меры: удалить все refresh токены для безопасности
      user.refreshTokens = [];
      await user.save();
      activeRefreshTokens.set(0);
      return res.status(401).json({
        message: "Refresh token reuse detected. All sessions cleared.",
      });
    }

    // Выполняем rotation: удаляем текущий токен и заменяем новым
    user.refreshTokens = user.refreshTokens.filter(
      (rt) => rt.tokenHash !== tokenHash
    );

    const newRefreshToken = signRefreshToken({
      userId: user._id,
      tokenId: crypto.randomUUID(),
    });
    const newHash = hashToken(newRefreshToken);
    user.refreshTokens.push({
      tokenHash: newHash,
      lastUsedAt: new Date(),
      deviceInfo: stored.deviceInfo,
    });
    await user.save();

    // issue new access token
    const payload = {
      userId: user._id,
      username: user.username,
      roles: user.roles,
    };
    const newAccessToken = signAccessToken(payload);

    logger.info("refresh_success", {
      userId: user._id,
      username: user.username,
    });
    refreshCount.inc();

    // метрика: обновить число активных refresh токенов
    activeRefreshTokens.set(user.refreshTokens.length);

    // вернуть новые токены
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: process.env.COOKIE_SECURE === "true",
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7,
      path: "/", // ← ЭТО ВАЖНО
    });
    res.json({ accessToken: newAccessToken });
  } catch (err) {
    logger.info("refresh_error", { err: err.message });
    authFailure.inc();
    return res.status(401).json({ message: "Invalid refresh token" });
  }
}

async function logout(req, res) {
  // console.log('=== DEBUG COOKIES LOGOUT ===');
  // console.log('1. req.cookies:', req.cookies); // должен быть объект
  // console.log('2. req.cookies?.refreshToken:', req.cookies?.refreshToken);
  // console.log('3. req.headers.cookie:', req.headers.cookie); // raw строка
  // console.log('=====================');
  const token = req.cookies?.refreshToken || req.body?.refreshToken;
  if (!token) return res.status(200).json({ message: "No token to logout" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) return res.status(200).json({ message: "Logged out" });

    const tokenHash = hashToken(token);
    user.refreshTokens = user.refreshTokens.filter(
      (rt) => rt.tokenHash !== tokenHash
    );
    await user.save();

    activeRefreshTokens.set(user.refreshTokens.length);
    logger.info("logout", { userId: user._id, username: user.username });
    res.clearCookie("refreshToken");
    res.status(200).json({ message: "Logged out" });
  } catch (err) {
    logger.error("logout_error", { err: err.message });
    res.status(500).json({ message: "Server error" });
  }
}

module.exports = {
  register,
  login,
  refresh,
  logout,
};
