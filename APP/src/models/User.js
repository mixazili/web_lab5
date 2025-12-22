// src/models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const SALT_ROUNDS = 12;

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  // храним хэши refresh токенов (поддержка нескольких устройств)
  refreshTokens: [
    {
      tokenHash: String,
      createdAt: { type: Date, default: Date.now },
      lastUsedAt: Date,
      deviceInfo: String,
    },
  ],
  roles: { type: [String], default: ['user'] },
  failedLoginAttempts: { type: Number, default: 0 },
  lastFailedAt: Date,
  createdAt: { type: Date, default: Date.now },
});

userSchema.methods.setPassword = async function(password) {
  this.passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
};

userSchema.methods.validatePassword = async function(password) {
  return bcrypt.compare(password, this.passwordHash);
};

module.exports = mongoose.model('User', userSchema);
