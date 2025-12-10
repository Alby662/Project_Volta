const request = require('supertest');
const jwt = require('jsonwebtoken');

// Mock the MongoDB and Playwright dependencies
jest.mock('mongodb', () => {
  const mockGridFSBucket = {
    openUploadStream: jest.fn().mockReturnThis(),
    openDownloadStream: jest.fn().mockReturnThis(),
    delete: jest.fn().mockResolvedValue(),
    end: jest.fn().mockImplementation((buffer, callback) => {
      callback(null, { id: 'mock-file-id' });
    })
  };
  
  const mockDb = {
    collection: jest.fn().mockReturnThis(),
    find: jest.fn().mockReturnThis(),
    sort: jest.fn().mockReturnThis(),
    toArray: jest.fn().mockResolvedValue([]),
    db: jest.fn().mockReturnThis()
  };
  
  return {
    MongoClient: {
      connect: jest.fn().mockResolvedValue({
        db: jest.fn().mockReturnValue(mockDb)
      })
    },
    GridFSBucket: jest.fn().mockImplementation(() => mockGridFSBucket),
    ObjectId: jest.fn().mockImplementation((id) => ({ toString: () => id }))
  };
});

jest.mock('playwright', () => ({
  chromium: {
    launch: jest.fn().mockResolvedValue({
      newContext: jest.fn().mockResolvedValue({
        newPage: jest.fn().mockResolvedValue({
          setContent: jest.fn().mockResolvedValue(),
          emulateMedia: jest.fn().mockResolvedValue(),
          waitForTimeout: jest.fn().mockResolvedValue(),
          pdf: jest.fn().mockResolvedValue(Buffer.from('mock-pdf-content'))
        })
      }),
      close: jest.fn().mockResolvedValue()
    })
  }
}));

// Import the actual server after mocking dependencies
let app;

describe('Authentication API', () => {
  beforeAll(() => {
    // Set environment variables
    process.env.JWT_SECRET = 'secretkey';
    
    // Clear any existing module cache
    jest.resetModules();
    // Import the server after mocking
    app = require('../server.js');
  });

  afterAll(async () => {
    // Clean up if needed
  });

  describe('POST /admin-login', () => {
    it('should authenticate with valid credentials and return a token', async () => {
      const response = await request(app)
        .post('/admin-login')
        .send({ username: 'admin', password: 'admin123' })
        .expect(200);

      expect(response.body).toHaveProperty('token');
      expect(typeof response.body.token).toBe('string');
      
      // Verify the token is valid
      const decoded = jwt.verify(response.body.token, 'secretkey');
      expect(decoded).toHaveProperty('id');
      expect(decoded).toHaveProperty('username');
      expect(decoded.username).toBe('admin');
    });

    it('should reject invalid credentials', async () => {
      const response = await request(app)
        .post('/admin-login')
        .send({ username: 'admin', password: 'wrongpassword' })
        .expect(401);

      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toBe('Invalid credentials');
    });

    it('should reject missing credentials', async () => {
      const response = await request(app)
        .post('/admin-login')
        .send({ username: 'admin' }) // Missing password
        .expect(401);

      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toBe('Invalid credentials');
    });

    it('should reject non-existent user', async () => {
      const response = await request(app)
        .post('/admin-login')
        .send({ username: 'nonexistent', password: 'password' })
        .expect(401);

      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toBe('Invalid credentials');
    });
  });

  describe('Authentication Middleware', () => {
    it('should reject requests without authorization header', async () => {
      const response = await request(app)
        .get('/all-reports')
        .expect(401);

      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toBe('No token');
    });

    it('should reject requests with invalid token', async () => {
      const response = await request(app)
        .get('/all-reports')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);

      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toBe('Invalid token');
    });

    it('should allow requests with valid token', async () => {
      // Generate a valid token
      const validToken = jwt.sign(
        { id: 1, username: 'admin' },
        'secretkey',
        { expiresIn: '1h' }
      );

      // This should pass authentication but may fail due to other reasons
      // We're just testing that authentication passes
      await request(app)
        .get('/all-reports')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);
    });
  });
});