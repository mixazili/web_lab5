global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

//   Или просто отключи console.log для тестов
// console.log = jest.fn();
// console.error = jest.fn();
