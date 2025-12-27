// Мокаем модули перед импортом
jest.mock("jsonwebtoken");
jest.mock("bcryptjs");
jest.mock("../../src/models/User");
jest.mock("../../src/config/logger");
jest.mock("../../src/config/monitor");

const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const User = require("../../src/models/User");
const authController = require("../../src/controllers/authController");
const { authSuccess, authFailure } = require("../../src/config/monitor");

// Создаем мок объекты
const mockUserInstance = {
  _id: "123",
  username: "test",
  roles: ["user"],
  refreshTokens: [],
  setPassword: jest.fn(),
  validatePassword: jest.fn(),
  save: jest.fn(),
};

describe("Auth Controller - Unit Tests", () => {
  beforeEach(() => {
    // Сбрасываем все моки
    jest.clearAllMocks();

    // Устанавливаем переменные окружения
    process.env.JWT_ACCESS_SECRET = "test_access_secret";
    process.env.JWT_REFRESH_SECRET = "test_refresh_secret";
    process.env.ACCESS_TOKEN_EXP = "15m";
    process.env.REFRESH_TOKEN_EXP = "7d";
    process.env.COOKIE_SECURE = "false";

    // Настраиваем моки по умолчанию
    User.findOne = jest.fn();
    User.findById = jest.fn();
    User.mockImplementation(() => mockUserInstance);

    // Моки для bcrypt
    bcrypt.hash = jest.fn();
    bcrypt.compare = jest.fn();

    // Моки для jwt
    jwt.sign = jest.fn();
    jwt.verify = jest.fn();

    // Моки для метрик
    authSuccess.inc = jest.fn();
    authFailure.inc = jest.fn();
  });

  describe("register", () => {
    test("should register new user successfully", async () => {
      // Arrange
      User.findOne.mockResolvedValue(null); // Пользователь не существует
      mockUserInstance.setPassword.mockResolvedValue();
      mockUserInstance.save.mockResolvedValue();

      const req = {
        body: { username: "test", password: "test123" },
      };
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };

      // Act
      await authController.register(req, res);

      // Assert
      expect(User.findOne).toHaveBeenCalledWith({ username: "test" });
      expect(mockUserInstance.setPassword).toHaveBeenCalledWith("test123");
      expect(mockUserInstance.save).toHaveBeenCalled();
      expect(authSuccess.inc).toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(201);
      expect(res.json).toHaveBeenCalledWith({ message: "Registered" });
    });

    test("should fail if user exists", async () => {
      // Arrange
      User.findOne.mockResolvedValue({ username: "test" });

      const req = {
        body: { username: "test", password: "test123" },
      };
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };

      // Act
      await authController.register(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ message: "User exists111" });
    });
  });

  describe("login", () => {
    test("should login successfully", async () => {
      // Arrange
      const mockUser = {
        _id: "123",
        username: "test",
        roles: ["user"],
        failedLoginAttempts: 0,
        lastFailedAt: null,
        refreshTokens: [],
        validatePassword: jest.fn().mockResolvedValue(true),
        save: jest.fn().mockResolvedValue(),
      };

      User.findOne.mockResolvedValue(mockUser);
      jwt.sign.mockReturnValue("mock_token");

      const req = {
        body: { username: "test", password: "test123" },
        get: jest.fn().mockReturnValue("test-agent"),
      };
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        cookie: jest.fn(),
      };

      // Act
      await authController.login(req, res);

      // Assert
      expect(mockUser.validatePassword).toHaveBeenCalledWith("test123");
      expect(jwt.sign).toHaveBeenCalled();
      expect(authSuccess.inc).toHaveBeenCalled();
      expect(res.cookie).toHaveBeenCalled();
      expect(res.json).toHaveBeenCalledWith({ accessToken: "mock_token" });
    });

    test("should fail with wrong password", async () => {
      // Arrange
      const mockUser = {
        _id: "123",
        username: "test",
        failedLoginAttempts: 0,
        lastFailedAt: null,
        refreshTokens: [],
        validatePassword: jest.fn().mockResolvedValue(false),
        save: jest.fn().mockResolvedValue(),
      };

      User.findOne.mockResolvedValue(mockUser);

      const req = {
        body: { username: "test", password: "wrong" },
        get: jest.fn().mockReturnValue("test-agent"),
      };
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };

      // Act
      await authController.login(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ message: "Invalid credentials" });
    });
  });

  describe("refresh", () => {
    test("should refresh token successfully", async () => {
      // Arrange
      const mockToken = "refresh_token";
      const mockDecoded = { userId: "123" };
      const mockUser = {
        _id: "123",
        username: "test",
        roles: ["user"],
        refreshTokens: [
          {
            tokenHash:
              "8a71ca93f1c2a6e4a7c8b5d9e0f3a2b1c4d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0",
          },
        ],
        save: jest.fn().mockResolvedValue(),
      };

      // Мокаем hashToken
      const crypto = require("crypto");
      const mockHash = crypto.createHash("sha256");
      mockHash.update = jest.fn().mockReturnThis();
      mockHash.digest = jest
        .fn()
        .mockReturnValue(
          "8a71ca93f1c2a6e4a7c8b5d9e0f3a2b1c4d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0"
        );

      // Подменяем createHash
      const originalCreateHash = crypto.createHash;
      crypto.createHash = jest.fn().mockReturnValue(mockHash);

      jwt.verify.mockReturnValue(mockDecoded);
      User.findById.mockResolvedValue(mockUser);
      jwt.sign.mockReturnValue("new_token");

      const req = {
        cookies: { refreshToken: mockToken },
        headers: { cookie: "refreshToken=refresh_token" },
      };
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        cookie: jest.fn(),
      };

      // Act
      await authController.refresh(req, res);

      // Assert
      expect(jwt.verify).toHaveBeenCalledWith(
        mockToken,
        process.env.JWT_REFRESH_SECRET
      );
      expect(User.findById).toHaveBeenCalledWith("123");
      expect(res.json).toHaveBeenCalledWith({ accessToken: "new_token" });

      // Восстанавливаем original
      crypto.createHash = originalCreateHash;
    });
  });
});
