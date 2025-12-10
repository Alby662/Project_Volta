// Jest setup file
// This file runs before each test file

// Set environment variables for testing
process.env.NODE_ENV = 'test';
process.env.PORT = '3001'; // Use different port for tests
process.env.MONGO_URI = 'mongodb://localhost:27017/test_db';
process.env.JWT_SECRET = 'secretkey'; // Match the hardcoded value in server.js

// Mock console methods to reduce noise during tests
global.console = {
  ...console,
  log: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

// Clean up after each test
afterEach(() => {
  jest.clearAllMocks();
});