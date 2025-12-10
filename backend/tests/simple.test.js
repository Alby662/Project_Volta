const request = require('supertest');
const jwt = require('jsonwebtoken');

// Set environment variables
process.env.JWT_SECRET = 'secretkey';
process.env.MONGO_URI = 'mongodb://localhost:27017/test_db';
process.env.DB_NAME = 'reportUploaderDB';

// Create mock objects
const mockGridFSBucket = {
  openUploadStream: jest.fn().mockReturnThis(),
  openDownloadStream: jest.fn().mockReturnThis(),
  delete: jest.fn().mockResolvedValue(),
  end: jest.fn().mockImplementation(function(buffer, callback) {
    // Call the callback immediately to simulate successful upload
    callback(null, { id: 'mock-file-id' });
    return this;
  })
};

// Mock the MongoDB and Playwright dependencies
jest.mock('mongodb', () => {
  // Create a mock database
  const mockDb = {
    collection: jest.fn().mockReturnThis(),
    find: jest.fn().mockReturnThis(),
    sort: jest.fn().mockReturnThis(),
    toArray: jest.fn().mockResolvedValue([
      {
        _id: 'report-1',
        filename: 'test_report.pdf',
        metadata: { folder: 1 },
        uploadDate: new Date('2023-01-01T00:00:00Z')
      }
    ]),
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

let app;
let validToken;

describe('Project Volta API Tests', () => {
  beforeAll(() => {
    // Clear any existing module cache
    jest.resetModules();
    // Import the server after mocking
    app = require('../server.js');
    
    // Generate a valid token for authenticated requests
    validToken = jwt.sign(
      { id: 1, username: 'admin' },
      'secretkey',
      { expiresIn: '1h' }
    );
  });

  describe('Authentication', () => {
    it('should authenticate with valid credentials and return a token', async () => {
      const response = await request(app)
        .post('/admin-login')
        .send({ username: 'admin', password: 'admin123' })
        .expect(200);

      expect(response.body).toHaveProperty('token');
      expect(typeof response.body.token).toBe('string');
    });

    it('should reject invalid credentials', async () => {
      const response = await request(app)
        .post('/admin-login')
        .send({ username: 'admin', password: 'wrongpassword' })
        .expect(401);

      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toBe('Invalid credentials');
    });
  });

  describe('Report Management', () => {
    it('should retrieve all reports when authenticated', async () => {
      const response = await request(app)
        .get('/all-reports')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
      expect(response.body.length).toBeGreaterThan(0);
    });

    it('should reject requests without authentication', async () => {
      const response = await request(app)
        .get('/all-reports')
        .expect(401);

      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toBe('No token');
    });

    it('should generate PDF with valid HTML and reportType', async () => {
      const response = await request(app)
        .post('/submit-report')
        .set('Authorization', `Bearer ${validToken}`)
        .send({
          html: '<html><body><h1>Test Report</h1></body></html>',
          reportType: 'liquid_ir',
          reportTitle: 'Test Report'
        })
        .expect(200);

      expect(response.body).toHaveProperty('fileId');
      expect(typeof response.body.fileId).toBe('string');
    });

    it('should retrieve PDF file by ID', async () => {
      // Mock the download stream to simulate successful PDF retrieval
      mockGridFSBucket.openDownloadStream.mockReturnValue({
        pipe: jest.fn()
      });

      const response = await request(app)
        .get('/get-pdf/report-1')
        .expect(200);

      expect(response.headers['content-type']).toContain('application/pdf');
    });

    it('should delete report when authenticated', async () => {
      const response = await request(app)
        .delete('/delete-report/report-1')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body.message).toBe('Report deleted successfully');
    });
  });
});