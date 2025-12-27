const request = require("supertest");

// Устанавливаем тестовые переменные окружения ПЕРЕД импортом server
process.env.MONGO_URI = "mongodb://127.0.0.1:27017/web_lab5_test";
process.env.JWT_ACCESS_SECRET = "test_access_secret";
process.env.JWT_REFRESH_SECRET = "test_refresh_secret";
process.env.ACCESS_TOKEN_EXP = "1m";
process.env.REFRESH_TOKEN_EXP = "10m";
process.env.COOKIE_SECURE = "false";
process.env.RATE_LIMIT_WINDOW_MS = "5000";
process.env.RATE_LIMIT_MAX = "1000";

// Импортируем приложение ПОСЛЕ установки переменных окружения
const { app, connectDB, disconnectDB } = require("../../src/server");

describe("Auth Integration Tests", () => {
  let agent;

  beforeAll(async () => {
    try {
      // Подключаемся к тестовой базе данных
      await connectDB();
    } catch (error) {
      console.error("Failed to connect to MongoDB:", error.message);
      throw error;
    }
  });

  beforeEach(() => {
    agent = request.agent(app);
  });

  afterEach(async () => {
    // Очищаем все коллекции после каждого теста
    const db = require("../../src/server").mongoose.connection.db;

    if (db) {
      try {
        const collections = await db.listCollections().toArray();

        for (const collection of collections) {
          try {
            await db.collection(collection.name).deleteMany({});
          } catch (error) {
            // Игнорируем ошибки очистки
          }
        }
      } catch (error) {
        // Игнорируем ошибки получения коллекций
      }
    }
  });

  afterAll(async () => {
    // Закрываем соединение с базой после всех тестов
    await disconnectDB();

    // Даем время для завершения всех операций
    await new Promise((resolve) => setTimeout(resolve, 100));
  });

  describe("POST /api/auth/register", () => {
    test("should register new user", async () => {
      const res = await agent.post("/api/auth/register").send({
        username: "testuser_" + Date.now(),
        password: "testpass123",
      });

      expect(res.status).toBe(201);
      expect(res.body).toHaveProperty("message", "Registered");
    });

    test("should not register duplicate user", async () => {
      const username = "duplicate_" + Date.now();

      // Первая регистрация
      await agent.post("/api/auth/register").send({
        username: username,
        password: "test123",
      });

      // Вторая попытка
      const res = await agent.post("/api/auth/register").send({
        username: username,
        password: "test123",
      });

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty("message", "User exists111");
    });
  });

  describe("POST /api/auth/login", () => {
    let testUsername;

    beforeEach(async () => {
      // Создаем пользователя для тестов входа
      testUsername = "loginuser_" + Date.now();
      await request(app)
        .post("/api/auth/register")
        .send({ username: testUsername, password: "loginpass" });
    });

    test("should login with correct credentials", async () => {
      const res = await agent.post("/api/auth/login").send({
        username: testUsername,
        password: "loginpass",
      });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty("accessToken");
      expect(res.headers["set-cookie"]).toBeDefined();
    });

    test("should fail with wrong password", async () => {
      const res = await agent.post("/api/auth/login").send({
        username: testUsername,
        password: "wrongpass",
      });

      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty("message", "Invalid credentials");
    });

    test("should fail with non-existent user", async () => {
      const res = await agent.post("/api/auth/login").send({
        username: "nonexistent_" + Date.now(),
        password: "somepass",
      });

      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty("message", "Invalid credentials");
    });
  });

  describe("POST /api/auth/refresh", () => {
    let refreshTokenCookie;
    let testUsername;

    beforeEach(async () => {
      // Регистрируем и логинимся
      testUsername = "refreshuser_" + Date.now();
      await agent.post("/api/auth/register").send({
        username: testUsername,
        password: "refreshpass",
      });

      const loginRes = await agent.post("/api/auth/login").send({
        username: testUsername,
        password: "refreshpass",
      });

      // Извлекаем refreshToken из заголовков Set-Cookie
      const setCookieHeaders = loginRes.headers["set-cookie"];
      if (Array.isArray(setCookieHeaders)) {
        // Находим куку с refreshToken
        const refreshCookie = setCookieHeaders.find((cookie) =>
          cookie.includes("refreshToken=")
        );
        if (refreshCookie) {
          // Извлекаем только значение куки (без атрибутов)
          refreshTokenCookie = refreshCookie.split(";")[0];
        }
      }
    });

    test("should refresh access token", async () => {
      // Используем сохраненные куки
      const res = await agent
        .post("/api/auth/refresh")
        .set("Cookie", refreshTokenCookie);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty("accessToken");
      expect(res.headers["set-cookie"]).toBeDefined();
    });

    test("should fail without refresh token", async () => {
      // Создаем нового агента без кук
      const newAgent = request.agent(app);
      const res = await newAgent.post("/api/auth/refresh");

      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty("message", "No refresh token");
    });
  });

  describe("POST /api/auth/logout", () => {
    test("should logout successfully", async () => {
      const username = "logoutuser_" + Date.now();

      // Сначала регистрируемся
      await agent.post("/api/auth/register").send({
        username: username,
        password: "logoutpass",
      });

      const loginRes = await agent.post("/api/auth/login").send({
        username: username,
        password: "logoutpass",
      });

      // Извлекаем refreshToken из заголовков Set-Cookie
      const setCookieHeaders = loginRes.headers["set-cookie"];
      let cookies = "";
      if (Array.isArray(setCookieHeaders)) {
        // Находим куку с refreshToken
        const refreshCookie = setCookieHeaders.find((cookie) =>
          cookie.includes("refreshToken=")
        );
        if (refreshCookie) {
          // Извлекаем только значение куки (без атрибутов)
          cookies = refreshCookie.split(";")[0];
        }
      }

      const res = await agent.post("/api/auth/logout").set("Cookie", cookies);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty("message", "Logged out");
    });
  });

  describe("GET /api/private", () => {
    test("should access protected route with valid token", async () => {
      const username = "privateuser_" + Date.now();

      // Регистрируем и логинимся
      await agent.post("/api/auth/register").send({
        username: username,
        password: "privatepass",
      });

      const loginRes = await agent.post("/api/auth/login").send({
        username: username,
        password: "privatepass",
      });

      const accessToken = loginRes.body.accessToken;

      const res = await request(app)
        .get("/api/private")
        .set("Authorization", `Bearer ${accessToken}`);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty("message", "Access granted");
      expect(res.body.user).toHaveProperty("username", username);
    });

    test("should fail without token", async () => {
      const res = await request(app).get("/api/private");

      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty("message", "No token");
    });

    test("should fail with invalid token", async () => {
      const res = await request(app)
        .get("/api/private")
        .set("Authorization", "Bearer invalid_token_here");

      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty("message", "Invalid token");
    });
  });
});
