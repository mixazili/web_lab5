const mongoose = require("mongoose");

beforeAll(async () => {
  // Подключаемся к тестовой БД
  await mongoose.connect("mongodb://127.0.0.1:27017/web_lab5_test");
});

afterEach(async () => {
  // Очищаем все коллекции после каждого теста
  const collections = mongoose.connection.collections;
  for (const key in collections) {
    await collections[key].deleteMany();
  }
});

afterAll(async () => {
  await mongoose.disconnect();
});
