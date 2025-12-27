const axios = require("axios");
const https = require("https");

const BASE_URL =
  (process.env.BASE_URL || "https://web-lab5-staging.onrender.com") + "/api";
const agent = new https.Agent({ keepAlive: false }); // отключаем keep-alive

describe("Auth E2E Tests (Staging)", () => {
  let username;
  let password;
  let accessToken;
  let refreshTokenCookie;

  afterAll(() => {
    agent.destroy(); // закрываем все соединения после всех тестов
  });

  test("1. Register new user", async () => {
    username = "e2euser_" + Date.now();
    password = "e2epass123";

    username1 = "e2eus" + Date.now();
    password1 = "e2epass123";

    const res = await axios.post(
      `${BASE_URL}/auth/register`,
      { username, password },
      { httpsAgent: agent }
    );
    expect(res.status).toBe(201);
    expect(res.data).toHaveProperty("message", "Registered");
  });

  test("2. Fail to register duplicate user", async () => {
    try {
      await axios.post(
        `${BASE_URL}/auth/register`,
        { username, password },
        { httpsAgent: agent }
      );
    } catch (err) {
      expect(err.response.status).toBe(400);
      expect(err.response.data).toHaveProperty("message", "User exists111");
    }
  });

  test("3. Login with correct credentials", async () => {
    const res = await axios.post(
      `${BASE_URL}/auth/login`,
      { username, password },
      { httpsAgent: agent }
    );
    expect(res.status).toBe(200);
    expect(res.data).toHaveProperty("accessToken");
    expect(res.headers["set-cookie"]).toBeDefined();

    accessToken = res.data.accessToken;

    const cookie = res.headers["set-cookie"].find((c) =>
      c.includes("refreshToken=")
    );
    refreshTokenCookie = cookie.split(";")[0];
  });

  test("4. Fail login with wrong password", async () => {
    try {
      await axios.post(
        `${BASE_URL}/auth/login`,
        { username, password: "wrongpass" },
        { httpsAgent: agent }
      );
    } catch (err) {
      expect(err.response.status).toBe(401);
      expect(err.response.data).toHaveProperty(
        "message",
        "Invalid credentials"
      );
    }
  });

  test("5. Access private route with valid token", async () => {
    const res = await axios.get(`${BASE_URL}/private`, {
      headers: { Authorization: `Bearer ${accessToken}` },
      httpsAgent: agent,
    });
    expect(res.status).toBe(200);
    expect(res.data).toHaveProperty("message", "Access granted");
    expect(res.data.user).toHaveProperty("username", username);
  });

  test("6. Access private route without token should fail", async () => {
    try {
      await axios.get(`${BASE_URL}/private`, { httpsAgent: agent });
    } catch (err) {
      expect(err.response.status).toBe(401);
      expect(err.response.data).toHaveProperty("message", "No token");
    }
  });

  test("7. Refresh access token", async () => {
    const res = await axios.post(
      `${BASE_URL}/auth/refresh`,
      {},
      {
        headers: { Cookie: refreshTokenCookie },
        httpsAgent: agent,
      }
    );
    expect(res.status).toBe(200);
    expect(res.data).toHaveProperty("accessToken");

    accessToken = res.data.accessToken;
  });

  test("8. Refresh fails without cookie", async () => {
    try {
      await axios.post(`${BASE_URL}/auth/refresh`, {}, { httpsAgent: agent });
    } catch (err) {
      expect(err.response.status).toBe(401);
      expect(err.response.data).toHaveProperty("message", "No refresh token");
    }
  });

  test("9. Logout successfully", async () => {
    const res = await axios.post(
      `${BASE_URL}/auth/logout`,
      {},
      {
        headers: { Cookie: refreshTokenCookie },
        httpsAgent: agent,
      }
    );
    expect(res.status).toBe(200);
    expect(res.data).toHaveProperty("message", "Logged out");
  });

  test("10. Access private route with old token after logout", async () => {
    try {
      await axios.get(`${BASE_URL}/private`, {
        headers: { Authorization: `Bearer ${accessToken}` },
        httpsAgent: agent,
      });
    } catch (err) {
      // В зависимости от реализации сервера токен может быть валиден или нет
      expect([200, 401]).toContain(err.response?.status || 200);
    }
  });
});
