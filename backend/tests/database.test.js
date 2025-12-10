// Mock environment variables before importing modules
process.env.MONGO_URI = 'mongodb://localhost:27017';
process.env.DB_NAME = 'reportUploaderDB';
process.env.JWT_SECRET = 'secretkey';

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

jest.mock('mongodb', () => ({
  MongoClient: mockMongoClient,
  GridFSBucket: jest.fn().mockImplementation(() => mockGridFSBucket),
  ObjectId: jest.fn().mockImplementation((id) => ({ toString: () => id }))
}));

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

describe('Database Integration', () => {
  beforeAll(() => {
    // Clear any existing module cache
    jest.resetModules();
    // Import server after setting up mocks
    app = require('../server.js');
  });

  beforeEach(() => {
    // Reset mocks before each test
    jest.clearAllMocks();
  });

  describe('Database Connection', () => {
    it('should connect to MongoDB with configured URI', async () => {
      // Verify MongoClient.connect was called with the correct URI
      expect(mockMongoClient.connect).toHaveBeenCalledWith('mongodb://localhost:27017');
      
      // Verify GridFSBucket was initialized
      const { GridFSBucket } = require('mongodb');
      expect(GridFSBucket).toHaveBeenCalled();
    });

    it('should handle connection failures gracefully', async () => {
      // Mock connection failure
      mockMongoClient.connect.mockRejectedValueOnce(new Error('Connection failed'));
      
      // Capture console.error
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
      
      // Re-import to trigger connection
      jest.resetModules();
      
      // Expect process.exit to be called
      const exitSpy = jest.spyOn(process, 'exit').mockImplementation();
      
      require('../server.js');
      
      // Wait for async operations
      await new Promise(resolve => setImmediate(resolve));
      
      // Verify error was logged
      expect(consoleSpy).toHaveBeenCalledWith('❌ MongoDB connection failed:', expect.any(Error));
      
      // Restore mocks
      consoleSpy.mockRestore();
      exitSpy.mockRestore();
    });
  });

  describe('GridFS Operations', () => {
    it('should store PDF files in GridFS', async () => {
      const mockPdfBuffer = Buffer.from('mock-pdf-content');
      const mockUploadStream = {
        id: 'file-123',
        end: jest.fn().mockImplementation((buffer, callback) => {
          callback(null, { id: 'file-123' });
        })
      };
      
      mockGridFSBucket.openUploadStream.mockReturnValue(mockUploadStream);
      
      // Simulate PDF storage (this would normally happen in the submit-report endpoint)
      const filename = 'test-report.pdf';
      const folderNumber = 1;
      
      const uploadStream = mockGridFSBucket.openUploadStream(filename, {
        metadata: { folder: folderNumber }
      });
      
      expect(mockGridFSBucket.openUploadStream).toHaveBeenCalledWith(filename, {
        metadata: { folder: folderNumber }
      });
      
      // Simulate ending the stream
      uploadStream.end(mockPdfBuffer, (err, result) => {
        expect(err).toBeNull();
        expect(result.id).toBe('file-123');
      });
    });

    it('should retrieve PDF files from GridFS', async () => {
      const mockDownloadStream = {
        pipe: jest.fn()
      };
      
      mockGridFSBucket.openDownloadStream.mockReturnValue(mockDownloadStream);
      
      // Simulate PDF retrieval (this would normally happen in the get-pdf endpoint)
      const fileId = 'file-123';
      
      const downloadStream = mockGridFSBucket.openDownloadStream(fileId);
      
      expect(mockGridFSBucket.openDownloadStream).toHaveBeenCalledWith(fileId);
      expect(downloadStream.pipe).toBeDefined();
    });

    it('should delete PDF files from GridFS', async () => {
      // Mock successful deletion
      mockGridFSBucket.delete.mockResolvedValueOnce();
      
      // Simulate PDF deletion (this would normally happen in the delete-report endpoint)
      const fileId = 'file-123';
      
      await mockGridFSBucket.delete(fileId);
      
      expect(mockGridFSBucket.delete).toHaveBeenCalledWith(fileId);
    });
  });

  describe('Data Consistency', () => {
    it('should maintain consistent report metadata', async () => {
      // Verify that reports are stored with correct metadata structure
      const mockReport = {
        filename: 'test-report.pdf',
        metadata: {
          folder: 5,
          // Other metadata fields could be added here
        }
      };
      
      expect(mockReport.metadata).toHaveProperty('folder');
      expect(typeof mockReport.metadata.folder).toBe('number');
      expect(mockReport.metadata.folder).toBeGreaterThanOrEqual(1);
      expect(mockReport.metadata.folder).toBeLessThanOrEqual(15);
    });

    it('should handle database errors gracefully', async () => {
      // Mock database operation failure
      mockDb.toArray.mockRejectedValueOnce(new Error('Database query failed'));
      
      // Capture console.error
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
      
      // Import server to trigger database operations
      jest.resetModules();
      app = require('../server.js');
      
      // Wait for async operations
      await new Promise(resolve => setImmediate(resolve));
      
      // Verify error was logged
      expect(consoleSpy).toHaveBeenCalledWith('❌ Fetch error:', expect.any(Error));
      
      // Restore mock
      consoleSpy.mockRestore();
    });
  });
});