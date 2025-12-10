const request = require('supertest');
const jwt = require('jsonwebtoken');

// Mock the MongoDB and Playwright dependencies
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
  }
];

const mockDb = {
  collection: jest.fn().mockReturnThis(),
  find: jest.fn().mockReturnThis(),
  sort: jest.fn().mockReturnThis(),
  toArray: jest.fn().mockResolvedValue(mockReports),
  db: jest.fn().mockReturnThis()
};

const mockMongoClient = {
  connect: jest.fn().mockResolvedValue({
    db: jest.fn().mockReturnValue(mockDb),
    close: jest.fn().mockResolvedValue()
  })
};

const mockPlaywright = {
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
};

jest.mock('mongodb', () => ({
  MongoClient: mockMongoClient,
  GridFSBucket: jest.fn().mockImplementation(() => mockGridFSBucket),
  ObjectId: jest.fn().mockImplementation((id) => ({ toString: () => id }))
}));

jest.mock('playwright', () => mockPlaywright);

let app;
let validToken;

describe('End-to-End Pipeline Tests', () => {
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

  beforeEach(() => {
    // Reset mocks before each test
    jest.clearAllMocks();
  });

  describe('Complete Report Generation Workflow', () => {
    const mockHtmlContent = `
      <!DOCTYPE html>
      <html>
        <head>
          <title>Test Report</title>
        </head>
        <body>
          <h1>Test Inspection Report</h1>
          <table>
            <tr>
              <td>Item 1</td>
              <td>Pass</td>
            </tr>
          </table>
        </body>
      </html>
    `;

    it('should complete full report generation pipeline', async () => {
      // Step 1: Authenticate
      const loginResponse = await request(app)
        .post('/admin-login')
        .send({ username: 'admin', password: 'admin123' })
        .expect(200);

      expect(loginResponse.body).toHaveProperty('token');
      const token = loginResponse.body.token;

      // Step 2: Submit report for PDF generation
      const submitResponse = await request(app)
        .post('/submit-report')
        .set('Authorization', `Bearer ${token}`)
        .send({
          html: mockHtmlContent,
          reportType: 'liquid_ir',
          reportTitle: 'Test Report'
        })
        .expect(200);

      expect(submitResponse.body).toHaveProperty('fileId');
      const fileId = submitResponse.body.fileId;

      // Verify Playwright was used for PDF generation
      expect(mockPlaywright.chromium.launch).toHaveBeenCalled();
      
      // Verify GridFS storage was used
      expect(mockGridFSBucket.openUploadStream).toHaveBeenCalled();
      expect(mockGridFSBucket.end).toHaveBeenCalled();

      // Step 3: Retrieve generated report
      const getResponse = await request(app)
        .get(`/get-pdf/${fileId}`)
        .expect(200);

      expect(getResponse.headers['content-type']).toContain('application/pdf');

      // Verify GridFS retrieval was used
      expect(mockGridFSBucket.openDownloadStream).toHaveBeenCalledWith(fileId);
    });

    it('should handle pipeline errors gracefully', async () => {
      // Mock Playwright to fail during PDF generation
      mockPlaywright.chromium.launch.mockRejectedValueOnce(new Error('Browser launch failed'));

      // Step 1: Authenticate
      const loginResponse = await request(app)
        .post('/admin-login')
        .send({ username: 'admin', password: 'admin123' })
        .expect(200);

      const token = loginResponse.body.token;

      // Step 2: Submit report (should fail during PDF generation)
      const submitResponse = await request(app)
        .post('/submit-report')
        .set('Authorization', `Bearer ${token}`)
        .send({
          html: mockHtmlContent,
          reportType: 'liquid_ir',
          reportTitle: 'Test Report'
        })
        .expect(500);

      expect(submitResponse.body).toHaveProperty('error');
      expect(submitResponse.body.error).toBe('Failed to generate PDF');
    });
  });

  describe('Admin Report Management Workflow', () => {
    it('should complete full report management pipeline', async () => {
      // Step 1: Authenticate
      const loginResponse = await request(app)
        .post('/admin-login')
        .send({ username: 'admin', password: 'admin123' })
        .expect(200);

      const token = loginResponse.body.token;

      // Step 2: List all reports
      const listResponse = await request(app)
        .get('/all-reports')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(Array.isArray(listResponse.body)).toBe(true);
      expect(listResponse.body.length).toBeGreaterThan(0);

      // Step 3: Retrieve a specific report
      const firstReportId = listResponse.body[0].fileId;
      const getResponse = await request(app)
        .get(`/get-pdf/${firstReportId}`)
        .expect(200);

      expect(getResponse.headers['content-type']).toContain('application/pdf');

      // Step 4: Delete the report
      const deleteResponse = await request(app)
        .delete(`/delete-report/${firstReportId}`)
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(deleteResponse.body).toHaveProperty('message');
      expect(deleteResponse.body.message).toBe('Report deleted successfully');

      // Verify GridFS deletion was used
      expect(mockGridFSBucket.delete).toHaveBeenCalledWith(firstReportId);
    });
  });

  describe('Authentication Flow', () => {
    it('should enforce authentication across all protected endpoints', async () => {
      // Test that protected endpoints reject unauthenticated requests
      const protectedEndpoints = [
        { method: 'GET', path: '/all-reports' },
        { method: 'POST', path: '/submit-report' },
        { method: 'DELETE', path: '/delete-report/report-1' }
      ];

      for (const endpoint of protectedEndpoints) {
        const response = await request(app)
          [endpoint.method.toLowerCase()](endpoint.path)
          .expect(401);

        expect(response.body).toHaveProperty('error');
        expect(response.body.error).toBe('No token');
      }
    });

    it('should allow access with valid token', async () => {
      // Test that protected endpoints allow access with valid token
      const response = await request(app)
        .get('/all-reports')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });
  });

  describe('Cross-Component Interactions', () => {
    it('should maintain data consistency across components', async () => {
      // Submit a report
      const submitResponse = await request(app)
        .post('/submit-report')
        .set('Authorization', `Bearer ${validToken}`)
        .send({
          html: '<html><body><h1>Test Report</h1></body></html>',
          reportType: 'liquid_ir',
          reportTitle: 'Test Report'
        })
        .expect(200);

      const fileId = submitResponse.body.fileId;

      // Verify the report appears in listings
      const listResponse = await request(app)
        .get('/all-reports?folder=1')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);

      const reportInList = listResponse.body.find(report => report.fileId === fileId);
      expect(reportInList).toBeDefined();
      expect(reportInList.filename).toContain('liquid_ir');

      // Verify the report can be retrieved
      await request(app)
        .get(`/get-pdf/${fileId}`)
        .expect(200);

      // Verify the report can be deleted
      await request(app)
        .delete(`/delete-report/${fileId}`)
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);
    });
  });
});