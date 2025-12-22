// Мокаем все зависимости перед тестами
jest.mock("jsonwebtoken");
jest.mock("bcryptjs");
jest.mock("../../src/models/User");
jest.mock("../../src/config/logger");
jest.mock("../../src/config/monitor");
