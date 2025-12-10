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
  
  const mockReports = [
    {
      _id: 'report-1',
      filename: 'liquid_ir_report.pdf',
      metadata: { folder: 1 },
      uploadDate: new Date('2023-01-01T00:00:00Z')
    },
    {
      _id: 'report-2',
      filename: 'vacuum_ir_report.pdf',
      metadata: { folder: 11 },
      uploadDate: new Date('2023-01-02T00:00:00Z')
    }
  ];
  
  const mockDb = {
    collection: jest.fn().mockReturnThis(),
    find: jest.fn().mockReturnThis(),
    sort: jest.fn().mockReturnThis(),
    toArray: jest.fn().mockResolvedValue(mockReports),
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

describe('Report Management API', () => {
  let validToken;

  beforeAll(() => {
    // Set environment variables
    process.env.JWT_SECRET = 'secretkey';
    
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

  describe('GET /all-reports', () => {
    it('should retrieve all reports when authenticated', async () => {
      const response = await request(app)
        .get('/all-reports')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
      expect(response.body.length).toBeGreaterThan(0);
      
      // Check structure of first report
      const firstReport = response.body[0];
      expect(firstReport).toHaveProperty('fileId');
      expect(firstReport).toHaveProperty('filename');
      expect(firstReport).toHaveProperty('folder');
      expect(firstReport).toHaveProperty('uploadDate');
    });

    it('should retrieve reports filtered by folder', async () => {
      const response = await request(app)
        .get('/all-reports?folder=1')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
      // All reports should have folder 1
      response.body.forEach(report => {
        expect(report.folder).toBe(1);
      });
    });

    it('should reject requests without authentication', async () => {
      const response = await request(app)
        .get('/all-reports')
        .expect(401);

      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toBe('No token');
    });
  });

  describe('GET /get-pdf/:fileId', () => {
    it('should retrieve PDF file by ID', async () => {
      const response = await request(app)
        .get('/get-pdf/report-1')
        .expect(200);

      expect(response.headers['content-type']).toContain('application/pdf');
    });

    it('should handle invalid file ID gracefully', async () => {
      // Mock ObjectId to throw an error for invalid IDs
      const { ObjectId } = require('mongodb');
      ObjectId.mockImplementationOnce(() => {
        throw new Error('Invalid ObjectId');
      });

      const response = await request(app)
        .get('/get-pdf/invalid-id')
        .expect(500);

      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toBe('Failed to retrieve PDF');
    });
  });

  describe('DELETE /delete-report/:fileId', () => {
    it('should delete report when authenticated', async () => {
      const response = await request(app)
        .delete('/delete-report/report-1')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body.message).toBe('Report deleted successfully');
    });

    it('should reject delete requests without authentication', async () => {
      const response = await request(app)
        .delete('/delete-report/report-1')
        .expect(401);

      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toBe('No token');
    });

    it('should handle delete errors gracefully', async () => {
      // Mock GridFSBucket delete to throw an error
      const { GridFSBucket } = require('mongodb');
      const mockBucket = GridFSBucket.mock.results[0].value;
      mockBucket.delete.mockRejectedValueOnce(new Error('Delete failed'));

      const response = await request(app)
        .delete('/delete-report/report-1')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(500);

      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toBe('Failed to delete report');
    });
  });
});