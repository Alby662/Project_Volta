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

describe('PDF Generation API', () => {
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

  describe('POST /submit-report', () => {
    const mockHtmlContent = '<html><body><h1>Test Report</h1></body></html>';
    
    it('should generate PDF with valid HTML and reportType', async () => {
      const response = await request(app)
        .post('/submit-report')
        .set('Authorization', `Bearer ${validToken}`)
        .send({
          html: mockHtmlContent,
          reportType: 'liquid_ir',
          reportTitle: 'Test Report'
        })
        .expect(200);

      expect(response.body).toHaveProperty('fileId');
      expect(typeof response.body.fileId).toBe('string');
    });

    it('should generate PDF with valid HTML and folder number', async () => {
      const response = await request(app)
        .post('/submit-report')
        .set('Authorization', `Bearer ${validToken}`)
        .send({
          html: mockHtmlContent,
          folder: 1,
          reportTitle: 'Test Report'
        })
        .expect(200);

      expect(response.body).toHaveProperty('fileId');
      expect(typeof response.body.fileId).toBe('string');
    });

    it('should reject requests without HTML content', async () => {
      const response = await request(app)
        .post('/submit-report')
        .set('Authorization', `Bearer ${validToken}`)
        .send({
          reportType: 'liquid_ir',
          reportTitle: 'Test Report'
        })
        .expect(400);

      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toBe('Missing HTML');
    });

    it('should reject requests without valid reportType or folder', async () => {
      const response = await request(app)
        .post('/submit-report')
        .set('Authorization', `Bearer ${validToken}`)
        .send({
          html: mockHtmlContent,
          reportTitle: 'Test Report'
        })
        .expect(400);

      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toBe('Missing or invalid reportType/folder (must map to 1-15)');
    });

    it('should reject requests with invalid folder number', async () => {
      const response = await request(app)
        .post('/submit-report')
        .set('Authorization', `Bearer ${validToken}`)
        .send({
          html: mockHtmlContent,
          folder: 20, // Invalid folder number
          reportTitle: 'Test Report'
        })
        .expect(400);

      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toBe('Missing or invalid reportType/folder (must map to 1-15)');
    });

    it('should handle PDF generation errors gracefully', async () => {
      // Mock Playwright to throw an error
      const playwright = require('playwright');
      playwright.chromium.launch.mockRejectedValueOnce(new Error('PDF generation failed'));

      const response = await request(app)
        .post('/submit-report')
        .set('Authorization', `Bearer ${validToken}`)
        .send({
          html: mockHtmlContent,
          reportType: 'liquid_ir',
          reportTitle: 'Test Report'
        })
        .expect(500);

      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toBe('Failed to generate PDF');
    });
  });

  // Test all report types
  describe('Report Type Validation', () => {
    const reportTypes = [
      'liquid_ir', 'draining_dry_ir', 'final_dimension_ir', 'hydrostatic_ir',
      'penetrating_oil_ir', 'pickling_pass_ir', 'raw_material_ir', 'rf_pad_ir',
      'stage_ir', 'surface_prep_paint_ir', 'vacuum_ir', 'visual_exam_ir',
      'extra1', 'extra2', 'extra3'
    ];

    reportTypes.forEach(reportType => {
      it(`should accept valid report type: ${reportType}`, async () => {
        const response = await request(app)
          .post('/submit-report')
          .set('Authorization', `Bearer ${validToken}`)
          .send({
            html: '<html><body><h1>Test Report</h1></body></html>',
            reportType: reportType,
            reportTitle: 'Test Report'
          })
          .expect(200);

        expect(response.body).toHaveProperty('fileId');
      });
    });
  });
});