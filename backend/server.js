require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { MongoClient, GridFSBucket, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const playwright = require("playwright");
const nodemailer = require("nodemailer");
const ejs = require("ejs");

// Logging system
const fs = require('fs');
const path = require('path');

// Create logs directory if it doesn't exist
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Log levels
const LOG_LEVELS = {
  ERROR: 0,
  WARN: 1,
  INFO: 2,
  DEBUG: 3
};

// Get current log level from environment or default to INFO
const currentLogLevel = process.env.LOG_LEVEL ? LOG_LEVELS[process.env.LOG_LEVEL.toUpperCase()] : LOG_LEVELS.INFO;

// Log file streams
const logFile = fs.createWriteStream(path.join(logsDir, 'app.log'), { flags: 'a' });
const errorFile = fs.createWriteStream(path.join(logsDir, 'error.log'), { flags: 'a' });

function log(level, message, metadata = null) {
  if (LOG_LEVELS[level] > currentLogLevel) return;

  const timestamp = new Date().toISOString();
  const logEntry = {
    timestamp,
    level,
    message,
    metadata
  };

  const logString = JSON.stringify(logEntry);

  // Write to console
  console.log(`[${timestamp}] ${level}: ${message}${metadata ? ' ' + JSON.stringify(metadata) : ''}`);

  // Write to appropriate log file
  if (level === 'ERROR') {
    errorFile.write(logString + '\n');
  } else {
    logFile.write(logString + '\n');
  }
}

// Report Type to Template File Mapping
const reportTemplates = {
  liquid: "liquid.ejs",
  vacuum: "vacuum.ejs",
  draining_dry: "draining_dry.ejs",
  final_dimension: "final_dimension.ejs",
  hydrostatic_test: "hydrostatic_test.ejs",
  oil_leak: "oil_leak.ejs",
  pickling_passivation: "pickling_passivation.ejs",
  raw_material: "raw_material.ejs",
  rf_pad_pneumatic: "rf_pad_pneumatic.ejs",
  surface_preparation_painting: "surface_preparation_painting.ejs",
  visual_examination: "visual_examination.ejs"
};

log('DEBUG', 'Report templates mapping loaded', { templateCount: Object.keys(reportTemplates).length, templates: Object.keys(reportTemplates) });

// Mapping from frontend report type keys to backend template keys
const frontendToBackendReportType = {
  'liquid_ir': 'liquid',
  'vacuum_ir': 'vacuum',
  'draining_dry_ir': 'draining_dry',
  'final_dimension_ir': 'final_dimension',
  'hydrostatic_ir': 'hydrostatic_test',
  'penetrating_oil_ir': 'oil_leak',
  'pickling_pass_ir': 'pickling_passivation',
  'raw_material_ir': 'raw_material',
  'rf_pad_ir': 'rf_pad_pneumatic',
  'surface_prep_paint_ir': 'surface_preparation_painting',
  'visual_exam_ir': 'visual_examination'
};

log('DEBUG', 'Frontend to backend report type mapping loaded', { mappingCount: Object.keys(frontendToBackendReportType).length, mappings: Object.keys(frontendToBackendReportType) });

// Email configuration
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "smtp.example.com",
  port: process.env.SMTP_PORT || 587,
  secure: false, // true for 465, false for other ports
  auth: {
    user: process.env.SMTP_USER || "user@example.com",
    pass: process.env.SMTP_PASS || "password",
  },
});

log('DEBUG', 'Server initialization', { 
  NODE_ENV: process.env.NODE_ENV,
  PORT: process.env.PORT,
  RENDER: process.env.RENDER,
  RENDER_SERVICE_NAME: process.env.RENDER_SERVICE_NAME
});

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true })); // Handle form submissions
app.use(express.static("public")); // Serve static files
app.set("view engine", "ejs"); // Set EJS as view engine

// Database configuration with connection pooling
const mongoURI = process.env.MONGO_URI || "mongodb://localhost:27017";
const dbName = process.env.DB_NAME || "reportUploaderDB";
const bucketName = "reports";

// MongoDB connection options with pooling
const mongoOptions = {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  maxPoolSize: 10, // Maximum number of connections in the pool
  minPoolSize: 5,  // Minimum number of connections in the pool
  maxIdleTimeMS: 30000, // Close connections after 30 seconds of inactivity
  serverSelectionTimeoutMS: 5000, // Timeout after 5 seconds
  socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
};

let db, bucket, mongoClient;

log('DEBUG', 'Connecting to MongoDB', { mongoURI, dbName, mongoOptions });

MongoClient.connect(mongoURI, mongoOptions)
  .then(client => {
    mongoClient = client;
    db = client.db(dbName);
    bucket = new GridFSBucket(db, { bucketName });
    log('INFO', 'MongoDB connected with connection pooling');

    // Initialize default admin user if it doesn't exist
    initializeDefaultUser();
  })
  .catch(err => {
    log('ERROR', 'MongoDB connection failed', { error: err.message, stack: err.stack });
    process.exit(1);
  });

// Browser instance management for performance
let browserInstance = null;
let browserUsageCount = 0;
const MAX_BROWSER_USAGE = 100; // Reuse browser instance for 100 requests

log('DEBUG', 'Browser instance management initialized', { MAX_BROWSER_USAGE });

async function getBrowserInstance() {
  log('DEBUG', 'getBrowserInstance called', { browserInstanceExists: !!browserInstance, browserUsageCount, MAX_BROWSER_USAGE });
  
  // Create new browser instance if none exists or if usage limit reached
  if (!browserInstance || browserUsageCount >= MAX_BROWSER_USAGE) {
    log('DEBUG', 'Creating new browser instance', { reason: !browserInstance ? 'no_instance' : 'usage_limit_reached' });
    
    if (browserInstance) {
      try {
        log('DEBUG', 'Closing previous browser instance');
        await browserInstance.close();
        log('DEBUG', 'Previous browser instance closed successfully');
      } catch (err) {
        log('WARN', 'Failed to close previous browser instance', { error: err.message });
      }
    }

    log('INFO', 'Launching browser for PDF generation');
    try {
      // Check if we're running on Render
      const isRender = process.env.RENDER === 'true' || !!process.env.RENDER_SERVICE_NAME;
      
      if (isRender) {
        log('INFO', 'Running on Render, using simplified browser launch options');
        // Simplified launch options for Render environment
        try {
          browserInstance = await playwright.chromium.launch({
            headless: true
          });
        } catch (renderLaunchError) {
          log('WARN', 'Standard Render launch failed, trying without specific options', { error: renderLaunchError.message });
          // Fallback to basic launch
          try {
            browserInstance = await playwright.chromium.launch({
              headless: true
            });
          } catch (fallbackError) {
            log('ERROR', 'All Render launch attempts failed', { 
              standardError: renderLaunchError.message,
              fallbackError: fallbackError.message
            });
            throw new Error(`Failed to launch browser on Render: ${renderLaunchError.message}. Fallback also failed: ${fallbackError.message}`);
          }
        }
      } else {
        // Standard launch options for local development
        try {
          browserInstance = await playwright.chromium.launch({
            headless: true,
            args: [
              '--no-sandbox', 
              '--disable-setuid-sandbox',
              '--disable-dev-shm-usage',
              '--disable-gpu',
              '--no-zygote'
            ]
          });
        } catch (standardLaunchError) {
          log('ERROR', 'Standard launch failed', { error: standardLaunchError.message });
          throw new Error(`Failed to launch browser with standard options: ${standardLaunchError.message}`);
        }
      }
      log('INFO', 'Browser launched successfully');
      browserUsageCount = 0;
      console.log("🚀 New browser instance created");
    } catch (launchError) {
      log('ERROR', 'Failed to launch browser', { 
        error: launchError.message, 
        stack: launchError.stack,
        // Add system info for debugging
        platform: process.platform,
        arch: process.arch,
        nodeVersion: process.version
      });
      
      // Try alternative launch options for Render
      try {
        log('INFO', 'Trying alternative browser launch options');
        browserInstance = await playwright.chromium.launch({
          headless: true
        });
        log('INFO', 'Browser launched successfully with alternative options');
        browserUsageCount = 0;
        console.log("🚀 New browser instance created (alternative)");
      } catch (altLaunchError) {
        log('ERROR', 'Failed to launch browser with alternative options', { 
          error: altLaunchError.message, 
          stack: altLaunchError.stack
        });
        throw new Error(`Failed to launch browser: ${launchError.message}. Alternative launch also failed: ${altLaunchError.message}`);
      }
    }
  }

  browserUsageCount++;
  log('DEBUG', 'Browser instance acquired', { browserUsageCount });
  return browserInstance;
}

// Audit trail collection name
const auditCollectionName = 'audit_trail';

function log(level, message, metadata = null) {
  if (LOG_LEVELS[level] > currentLogLevel) return;

  const timestamp = new Date().toISOString();
  const logEntry = {
    timestamp,
    level,
    message,
    metadata
  };

  const logString = JSON.stringify(logEntry);

  // Log to console
  console.log(`[${timestamp}] ${level}: ${message}`);

  // Log to file
  logFile.write(logString + '\n');

  // Log errors to separate error file
  if (level === 'ERROR') {
    errorFile.write(logString + '\n');
  }

  // Save to database for audit trail (only for important events)
  if (db && (level === 'INFO' || level === 'WARN' || level === 'ERROR')) {
    try {
      const auditEntry = {
        timestamp: new Date(),
        level,
        message,
        metadata,
        userId: metadata?.userId || null
      };

      // Insert audit log entry (non-blocking)
      db.collection(auditCollectionName).insertOne(auditEntry).catch(err => {
        console.error('Failed to save audit log to database:', err);
      });
    } catch (err) {
      console.error('Error in audit logging:', err);
    }
  }
}

// Middleware for request logging
function requestLogger(req, res, next) {
  const start = Date.now();

  // Log request
  log('INFO', 'Incoming request', {
    method: req.method,
    url: req.url,
    ip: req.ip || req.connection.remoteAddress,
    userAgent: req.get('User-Agent')
  });

  // Log response
  res.on('finish', () => {
    const duration = Date.now() - start;
    log('INFO', 'Request completed', {
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      duration: `${duration}ms`
    });
  });

  next();
}

// Apply request logging middleware
app.use(requestLogger);

// Graceful shutdown
process.on('SIGINT', async () => {
  log('INFO', 'Shutting down gracefully');
  if (mongoClient) {
    await mongoClient.close();
    log('INFO', 'MongoDB connection closed');
  }
  if (browserInstance) {
    await browserInstance.close();
    log('INFO', 'Browser instance closed');
  }
  process.exit(0);
});

async function initializeDefaultUser() {
  try {
    const usersCollection = db.collection('users');
    const adminUser = await usersCollection.findOne({ username: "admin" });

    if (!adminUser) {
      // Hash the default password
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash("admin123", saltRounds);

      await usersCollection.insertOne({
        username: "admin",
        password: hashedPassword,
        role: "admin",
        createdAt: new Date()
      });

      log('INFO', 'Default admin user created');
    } else {
      log('INFO', 'Admin user already exists');
    }
  } catch (err) {
    log('ERROR', 'Error initializing default user', { error: err.message });
  }
}

// === Mapping of reportType keys to folder numbers (1..15) ===
// This must match the admin panel folder ordering.
const reportTypeToFolder = {
  liquid_ir: 1,
  draining_dry_ir: 2,
  final_dimension_ir: 3,
  hydrostatic_ir: 4,
  penetrating_oil_ir: 5,
  pickling_pass_ir: 6,
  raw_material_ir: 7,
  rf_pad_ir: 8,
  stage_ir: 9,
  surface_prep_paint_ir: 10,
  vacuum_ir: 11,
  visual_exam_ir: 12,
  extra1: 13,
  extra2: 14,
  extra3: 15
};

function generateToken(user) {
  return jwt.sign({ id: user._id, username: user.username, role: user.role }, process.env.JWT_SECRET || "secretkey", {
    expiresIn: "1h",
  });
}

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });

  jwt.verify(token, process.env.JWT_SECRET || "secretkey", (err, decoded) => {
    if (err) return res.status(401).json({ error: "Invalid token" });
    req.user = decoded;
    next();
  });
}

function checkRole(role) {
  return (req, res, next) => {
    if (req.user && req.user.role === role) {
      next();
    } else {
      res.status(403).json({ error: "Access denied. Insufficient permissions." });
    }
  };
}

// Enhanced rate limiting middleware with configuration
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000; // 15 minutes
const RATE_LIMIT_MAX_REQUESTS = process.env.RATE_LIMIT_MAX_REQUESTS || 10; // 10 requests per window

function rateLimitMiddleware(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  const windowMs = parseInt(RATE_LIMIT_WINDOW_MS);
  const maxRequests = parseInt(RATE_LIMIT_MAX_REQUESTS);

  if (!rateLimitMap.has(ip)) {
    rateLimitMap.set(ip, {
      requests: [{ timestamp: now }],
      resetTime: now + windowMs
    });
    return next();
  }

  const rateLimitInfo = rateLimitMap.get(ip);

  // Reset if window has passed
  if (now > rateLimitInfo.resetTime) {
    rateLimitMap.set(ip, {
      requests: [{ timestamp: now }],
      resetTime: now + windowMs
    });
    return next();
  }

  // Remove old requests
  rateLimitInfo.requests = rateLimitInfo.requests.filter(request =>
    request.timestamp > now - windowMs
  );

  // Check if limit exceeded
  if (rateLimitInfo.requests.length >= maxRequests) {
    return res.status(429).json({
      error: `Too many requests, please try again after ${Math.ceil((rateLimitInfo.resetTime - now) / 1000)} seconds`
    });
  }

  // Add current request
  rateLimitInfo.requests.push({ timestamp: now });
  next();
}

// Cleanup old rate limit entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [ip, rateLimitInfo] of rateLimitMap.entries()) {
    if (now > rateLimitInfo.resetTime + 300000) { // Remove entries 5 minutes after reset
      rateLimitMap.delete(ip);
    }
  }
}, 300000); // Run cleanup every 5 minutes

app.get("/", (req, res) => {
  res.redirect("/admin");
});

// Render Liquid Report
app.get("/reports/liquid", (req, res) => {
  res.render("reports/liquid");
});

// Render Vacuum Report
app.get("/reports/vacuum", (req, res) => {
  res.render("reports/vacuum");
});

// Render Draining & Dry Report
app.get("/reports/draining_dry", (req, res) => {
  res.render("reports/draining_dry");
});

// Render Final Dimension Report
app.get("/reports/final_dimension", (req, res) => {
  res.render("reports/final_dimension");
});

// Render Hydrostatic Test Report
app.get("/reports/hydrostatic_test", (req, res) => {
  res.render("reports/hydrostatic_test");
});

// Render Oil Leak Test Report
app.get("/reports/oil_leak", (req, res) => {
  res.render("reports/oil_leak");
});

// Render Pickling & Passivation Report
app.get("/reports/pickling_passivation", (req, res) => {
  res.render("reports/pickling_passivation");
});

// Render Raw Material Report
app.get("/reports/raw_material", (req, res) => {
  res.render("reports/raw_material");
});

// Render RF-PAD Pneumatic Test Report
app.get("/reports/rf_pad_pneumatic", (req, res) => {
  res.render("reports/rf_pad_pneumatic");
});

// Render Visual Examination Report
app.get("/reports/visual_examination", (req, res) => {
  res.render("reports/visual_examination");
});

// Render Surface Preparation & Painting Report
app.get("/reports/surface_preparation_painting", (req, res) => {
  res.render("reports/surface_preparation_painting");
});

// Render Dashboard
app.get("/dashboard", (req, res) => {
  res.render("dashboard");
});

// Render Report Catalog
app.get("/report-catalog", (req, res) => {
  res.render("report-catalog");
});

// Render Admin Login
app.get("/admin", (req, res) => {
  res.render("admin");
});

// Render All Reports Archive
app.get("/all-reports.html", (req, res) => {
  res.render("all-reports");
});

function validateReportInput(html, reportType, folder, reportTitle) {
  const errors = [];

  // Validate HTML
  if (!html || typeof html !== 'string') {
    errors.push('HTML content is required');
  } else if (html.length > 1000000) { // 1MB limit
    errors.push('HTML content is too large');
  }

  // Validate reportTitle
  if (!reportTitle || typeof reportTitle !== 'string') {
    errors.push('Report title is required');
  } else if (reportTitle.length > 200) {
    errors.push('Report title is too long (max 200 characters)');
  }

  // Validate reportType if provided
  if (reportType !== undefined && reportType !== null) {
    if (typeof reportType !== 'string') {
      errors.push('Report type must be a string');
    } else if (reportType.length > 50) {
      errors.push('Report type is too long (max 50 characters)');
    }
  }

  // Validate folder if provided
  if (folder !== undefined && folder !== null) {
    if (typeof folder !== 'number' && typeof folder !== 'string') {
      errors.push('Folder must be a number or string');
    } else {
      const folderNum = typeof folder === 'string' ? parseInt(folder, 10) : folder;
      if (isNaN(folderNum) || folderNum < 1 || folderNum > 15) {
        errors.push('Folder must be between 1 and 15');
      }
    }
  }

  // Either reportType or folder must be provided
  if ((reportType === undefined || reportType === null || reportType === '') &&
    (folder === undefined || folder === null || folder === '')) {
    errors.push('Either reportType or folder is required');
  }

  return errors;
}

function validateUserInput(username, password) {
  const errors = [];

  // Validate username
  if (!username || typeof username !== 'string') {
    errors.push('Username is required');
  } else if (username.length < 3) {
    errors.push('Username must be at least 3 characters');
  } else if (username.length > 50) {
    errors.push('Username is too long (max 50 characters)');
  } else if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    errors.push('Username can only contain letters, numbers, and underscores');
  }

  // Validate password
  if (!password || typeof password !== 'string') {
    errors.push('Password is required');
  } else if (password.length < 6) {
    errors.push('Password must be at least 6 characters');
  } else if (password.length > 100) {
    errors.push('Password is too long (max 100 characters)');
  }

  return errors;
}

// Standardized error response function
function sendErrorResponse(res, statusCode, message, details = null) {
  const response = { error: message };
  if (process.env.NODE_ENV === 'development' && details) {
    response.details = details;
  }
  return res.status(statusCode).json(response);
}

app.post("/admin-login", rateLimitMiddleware, async (req, res) => {
  const { username, password } = req.body;

  log('INFO', 'Login attempt', { username });

  // Validate input
  const validationErrors = validateUserInput(username, password);
  if (validationErrors.length > 0) {
    log('WARN', 'Login validation failed', { username, errors: validationErrors });
    return sendErrorResponse(res, 400, validationErrors.join(', '));
  }

  try {
    const usersCollection = db.collection('users');
    const user = await usersCollection.findOne({ username: username });

    if (!user) {
      // Consistent error message to prevent username enumeration
      log('WARN', 'Login failed - user not found', { username });
      return sendErrorResponse(res, 401, "Invalid credentials");
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      log('WARN', 'Login failed - invalid password', { username });
      return sendErrorResponse(res, 401, "Invalid credentials");
    }

    log('INFO', 'Login successful', { username, userId: user._id });
    res.json({ token: generateToken(user) });
  } catch (err) {
    log('ERROR', 'Login error', { 
      username, 
      error: err.message, 
      stack: err.stack,
      // Check if db is still connected
      dbConnected: !!db?.serverConfig?.isConnected()
    });
    sendErrorResponse(res, 500, "Login failed", err.message);
  }
});

// User registration endpoint (for future use)
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  // Validate input
  const validationErrors = validateUserInput(username, password);
  if (validationErrors.length > 0) {
    return sendErrorResponse(res, 400, validationErrors.join(', '));
  }

  try {
    const usersCollection = db.collection('users');
    const existingUser = await usersCollection.findOne({ username: username });

    if (existingUser) {
      return sendErrorResponse(res, 400, "Username already exists");
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const newUser = {
      username: username,
      password: hashedPassword,
      role: "user",
      createdAt: new Date()
    };

    const result = await usersCollection.insertOne(newUser);
    res.status(201).json({ message: "User created successfully", userId: result.insertedId });
  } catch (err) {
    log('ERROR', 'Registration error', { 
      error: err.message, 
      stack: err.stack,
      // Check if db is still connected
      dbConnected: !!db?.serverConfig?.isConnected()
    });
    sendErrorResponse(res, 500, "Registration failed", err.message);
  }
});

// API: Save Report (with file uploads)
// API: Get Report HTML for Preview
app.get("/api/report-html/:reportId", async (req, res) => {
  try {
    const { reportId } = req.params;
    
    if (!reportId) {
      return sendErrorResponse(res, 400, 'Report ID is required');
    }
    
    log('INFO', 'Report HTML request for preview', { reportId });
    
    log('DEBUG', 'Accessing saved_reports collection in preview endpoint');
    const reportsCollection = db.collection('saved_reports');
    log('DEBUG', 'Finding report by ID in preview endpoint', { reportId });
    const report = await reportsCollection.findOne({ _id: new ObjectId(reportId) });
    
    if (!report) {
      log('WARN', 'Report not found for preview', { reportId });
      return sendErrorResponse(res, 404, 'Report not found');
    }
    
    let reportType = report.reportType;
    
    log('DEBUG', 'Processing report type in preview endpoint', { originalReportType: report.reportType });
    
    // Convert frontend report type to backend report type if needed
    if (frontendToBackendReportType[reportType]) {
      reportType = frontendToBackendReportType[reportType];
      log('DEBUG', 'Converted report type in preview endpoint', { original: report.reportType, converted: reportType });
    }
    
    const formData = report.formData || {};
    const templateFile = reportTemplates[reportType];
    
    log('DEBUG', 'Template file resolution in preview', { reportType, templateFile, availableTemplates: Object.keys(reportTemplates) });
    
    if (!templateFile) {
      log('ERROR', 'No template file found for report type', { 
        reportType, 
        availableTemplates: Object.keys(reportTemplates)
      });
      return sendErrorResponse(res, 400, `Unknown report type template for: ${reportType}`);
    }
    
    // Render EJS Template
    const templatePath = path.join(__dirname, 'views', 'reports', templateFile);
    
    // Check if template file exists
    if (!fs.existsSync(templatePath)) {
      log('ERROR', 'Template file not found', { templatePath, reportType });
      return sendErrorResponse(res, 500, `Template file not found: ${templateFile}`);
    }
    
    // Pass data for EJS rendering
    const renderData = {
      ...formData,
      reportName: report.reportName || reportType.replace(/_/g, ' ').toUpperCase() + ' REPORT',
      title: report.reportName || reportType.replace(/_/g, ' ').toUpperCase()
    };
    
    let htmlContent = await ejs.renderFile(templatePath, renderData, {
      root: path.join(__dirname, 'views')
    });
    
    res.json({
      success: true,
      html: htmlContent
    });
    
  } catch (err) {
    log('ERROR', 'Failed to generate report HTML', { 
      error: err.message, 
      stack: err.stack,
      // Check if db is still connected
      dbConnected: !!db?.serverConfig?.isConnected()
    });
    sendErrorResponse(res, 500, 'Failed to generate report HTML', err.message);
  }
});

app.post("/api/save-report", async (req, res) => {
  try {
    let reportType = req.body.reportType || 'unknown';
    
    // Convert frontend report type to backend report type if needed
    if (frontendToBackendReportType[reportType]) {
      reportType = frontendToBackendReportType[reportType];
    }
    
    const timestamp = new Date().toISOString();

    // Extract form data (exclude reportType and reportName from formData)
    // If formData is explicitly provided, use it; otherwise extract from request body
    let formData;
    if (req.body.formData) {
      // Use explicitly provided formData
      const { reportType: rt, reportName: rn, ...extractedFormData } = req.body.formData;
      formData = extractedFormData;
      log('DEBUG', 'Using explicit formData from request', { formDataKeys: Object.keys(formData) });
    } else {
      // Extract form data from request body (fallback for backward compatibility)
      const { reportType: rt, reportName: rn, ...extractedFormData } = req.body;
      formData = extractedFormData;
      log('DEBUG', 'Extracted formData from request body', { formDataKeys: Object.keys(formData) });
    }
    
    // Extract reportName from formData if available, otherwise use reportType
    let reportName = req.body.reportName || reportType;
    if (req.body.formData && req.body.formData.reportName) {
      reportName = req.body.formData.reportName;
    }
    
    log('INFO', 'Report save request', { reportType, reportName, hasFormData: !!formData, formDataKeys: Object.keys(formData).length });
    
    const reportDocument = {
      reportType,
      reportName: reportName || reportType, // Use friendly name if available
      formData,
      createdAt: timestamp,
      status: 'draft'
    };

    const reportsCollection = db.collection('saved_reports');
    const result = await reportsCollection.insertOne(reportDocument);

    log('INFO', 'Report saved successfully', { reportId: result.insertedId });

    res.json({
      success: true,
      message: 'Report saved successfully',
      reportId: result.insertedId
    });

  } catch (err) {
    log('ERROR', 'Failed to save report', { 
      error: err.message, 
      stack: err.stack,
      // Check if db is still connected
      dbConnected: !!db?.serverConfig?.isConnected()
    });
    sendErrorResponse(res, 500, 'Failed to save report', err.message);
  }
});

// API: Get Saved Reports
app.get("/api/saved-reports", async (req, res) => {
  try {
    log('INFO', 'Fetching saved reports');

    log('DEBUG', 'Accessing saved_reports collection in get reports endpoint');
    const reportsCollection = db.collection('saved_reports');
    
    // Check if collection exists and has data
    try {
      const count = await reportsCollection.countDocuments({});
      log('DEBUG', 'Saved reports collection stats', { count });
    } catch (countErr) {
      log('WARN', 'Failed to count documents in saved_reports', { error: countErr.message });
    }
    
    const reports = await reportsCollection
      .find({})
      .sort({ createdAt: -1 })
      .toArray();

    const reportList = reports.map(report => ({
      _id: report._id,
      reportType: report.reportType,
      createdAt: report.createdAt,
      status: report.status,
      // Extract some key fields for preview
      preview: {
        reportNo: report.formData?.report_no || report.formData?.reportNo || 'N/A',
        customer: report.formData?.customer || 'N/A'
      }
    }));

    log('INFO', 'Saved reports fetched', { count: reportList.length });
    res.json(reportList);

  } catch (err) {
    log('ERROR', 'Failed to fetch saved reports', { 
      error: err.message, 
      stack: err.stack,
      // Check if db is still connected
      dbConnected: !!db?.serverConfig?.isConnected()
    });
    sendErrorResponse(res, 500, 'Failed to fetch saved reports', err.message);
  }
});

// API: Export Saved Report to PDF
app.post("/api/export-pdf/:reportId", async (req, res) => {
  try {
    const reportId = req.params.reportId;
    
    log('DEBUG', 'Checking ObjectId validity in export endpoint', { reportId, isValid: ObjectId.isValid(reportId) });

    if (!ObjectId.isValid(reportId)) {
      log('WARN', 'Invalid report ID provided in export endpoint', { reportId });
      return sendErrorResponse(res, 400, 'Invalid report ID');
    }

    log('INFO', 'PDF export request', { reportId });

    log('DEBUG', 'Accessing saved_reports collection in export endpoint');
    const reportsCollection = db.collection('saved_reports');
    log('DEBUG', 'Finding report by ID in export endpoint', { reportId });
    const report = await reportsCollection.findOne({ _id: new ObjectId(reportId) });

    if (!report) {
      log('WARN', 'Report not found for export', { reportId });
      return sendErrorResponse(res, 404, 'Report not found');
    }
    
    log('DEBUG', 'Report found for export', { 
      reportId, 
      reportType: report.reportType, 
      hasFormData: !!report.formData, 
      formDataKeys: report.formData ? Object.keys(report.formData) : [],
      reportKeys: Object.keys(report)
    });

    let reportType = report.reportType;
    
    log('DEBUG', 'Processing report type in export endpoint', { originalReportType: report.reportType });
    
    // Convert frontend report type to backend report type if needed
    log('DEBUG', 'Checking report type conversion', { originalReportType: reportType, availableMappings: Object.keys(frontendToBackendReportType) });
    if (frontendToBackendReportType[reportType]) {
      reportType = frontendToBackendReportType[reportType];
      log('DEBUG', 'Converted report type in export endpoint', { original: report.reportType, converted: reportType });
    } else {
      // Also check if we need to convert from backend to frontend mapping
      // This handles cases where the stored reportType is in backend format
      const reverseMapping = {};
      Object.keys(frontendToBackendReportType).forEach(key => {
        reverseMapping[frontendToBackendReportType[key]] = key;
      });
      
      if (reverseMapping[reportType]) {
        log('DEBUG', 'Using reverse mapping for report type', { original: reportType, mapped: reverseMapping[reportType] });
        // Don't change the reportType here, we're just checking
      }
    }
    
    const formData = report.formData || {};
    const templateFile = reportTemplates[reportType];
    
    log('DEBUG', 'Template file resolution', { reportType, templateFile, availableTemplates: Object.keys(reportTemplates) });

    log('INFO', 'Generating PDF for report', { reportType, templateFile, reportId, reportDataKeys: Object.keys(report) });

    // Log detailed report information for debugging
    log('DEBUG', 'Report data details', { 
      reportId, 
      reportType, 
      hasFormData: !!report.formData, 
      formDataKeys: report.formData ? Object.keys(report.formData) : [],
      availableTemplates: Object.keys(reportTemplates)
    });

    if (!templateFile) {
      log('ERROR', 'No template file found for report type', { 
        reportType, 
        availableTemplates: Object.keys(reportTemplates)
      });
      
      // Log report types in database asynchronously
      db.collection('saved_reports').distinct('reportType')
        .then(types => log('DEBUG', 'Report types in database', { types }))
        .catch(err => log('ERROR', 'Failed to get report types', { error: err.message }));
      return sendErrorResponse(res, 400, `Unknown report type template for: ${reportType}. Available templates: ${Object.keys(reportTemplates).join(', ')}`);
    }

    // 1. Render EJS Template
    const templatePath = path.join(__dirname, 'views', 'reports', templateFile);
    
    log('DEBUG', 'Template path check', { templatePath, templateFile, __dirname });
    
    // Check if template file exists
    const templateExists = fs.existsSync(templatePath);
    log('DEBUG', 'Template file existence check', { templatePath, templateExists });
    
    if (!templateExists) {
      log('ERROR', 'Template file not found', { templatePath, reportType });
      return sendErrorResponse(res, 500, `Template file not found: ${templateFile}`);
    }

    // Pass basic data for EJS partials (header/footer usually need specific vars)
    // We pass formData as locals too, just in case some templates use it.
    const renderData = {
      ...formData,
      reportName: report.reportName || reportType.replace(/_/g, ' ').toUpperCase() + ' REPORT',
      title: report.reportName || reportType.replace(/_/g, ' ').toUpperCase()
    };

    log('DEBUG', 'Rendering EJS template', { templatePath, renderDataKeys: Object.keys(renderData) });
    let htmlContent = await ejs.renderFile(templatePath, renderData, {
      root: path.join(__dirname, 'views') // Ensure includes work
    });
    log('DEBUG', 'EJS template rendered', { contentLength: htmlContent.length });

    // 2. Inject CSS
    const cssPath = path.join(__dirname, 'public', 'css', 'style.css');
    log('DEBUG', 'CSS path check', { cssPath });
    
    let cssContent = '';
    try {
      const cssExists = fs.existsSync(cssPath);
      log('DEBUG', 'CSS file existence check', { cssPath, cssExists });
      
      if (cssExists) {
        cssContent = fs.readFileSync(cssPath, 'utf8');
        log('DEBUG', 'CSS file read successfully', { cssLength: cssContent.length });
      } else {
        log('WARN', 'CSS file not found', { cssPath });
      }
    } catch (e) {
      log('WARN', 'Failed to read style.css for PDF export', { error: e.message });
    }

    // Inject CSS into head
    // We append our print-specific styles too to ensure inputs look like text
    log('DEBUG', 'Injecting CSS', { cssLength: cssContent.length });
    const styleInjection = `
    <style>
        ${cssContent}
        /* PDF Specific Overrides */
        body { background: white !important; -webkit-print-color-adjust: exact; }
        .container { width: 100% !important; max-width: none !important; margin: 0 !important; padding: 20px !important; }
        input, textarea, select { border: none !important; background: transparent !important; resize: none; appearance: none; padding: 0 !important; }
        .no-print { display: none !important; }
        button { display: none !important; }
        @page { size: A4; margin: 10mm; }
    </style>`;

    htmlContent = htmlContent.replace('</head>', `${styleInjection}</head>`);
    log('DEBUG', 'CSS injected', { newContentLength: htmlContent.length });

    // 3. Pre-process Images to Base64 (The "Nuclear Option" for Reliability)
    // This avoids all localhost/network/timing issues by embedding the image directly
    // 3. Pre-process Images to Base64 (The "Nuclear Option" for Reliability)
    // This avoids all localhost/network/timing issues by embedding the image directly

    // Determine which logo to use: selected or default
    const logoToUse = formData.logo_select || '/images/logo.jpg';
    
    log('DEBUG', 'Processing logo for PDF', { logoToUse, formDataLogoSelect: formData.logo_select });

    if (logoToUse) {
      try {
        // Remove leading slash to join correctly
        const relativePath = logoToUse.startsWith('/') ? logoToUse.slice(1) : logoToUse;
        const imagePath = path.join(__dirname, 'public', relativePath);
        
        log('DEBUG', 'Checking logo path', { imagePath, relativePath });
        const imageExists = fs.existsSync(imagePath);
        log('DEBUG', 'Logo file existence check', { imagePath, imageExists });

        if (imageExists) {
          const imageBuffer = fs.readFileSync(imagePath);
          const ext = path.extname(imagePath).slice(1); // jpg or png
          const base64Image = `data:image/${ext};base64,${imageBuffer.toString('base64')}`;

          // create a specific field for the processed logo to inject
          formData.processed_logo = base64Image;
          log('INFO', 'Logo converted to base64 successfully', { path: imagePath, base64Length: base64Image.length });
        } else {
          log('WARN', 'Logo file not found', { path: imagePath });
          // If specific logo missing, try hard fallback to known default
          if (relativePath !== 'images/logo.jpg') {
            const defaultPath = path.join(__dirname, 'public', 'images', 'logo.jpg');
            log('DEBUG', 'Checking default logo path', { defaultPath });
            const defaultExists = fs.existsSync(defaultPath);
            log('DEBUG', 'Default logo file existence check', { defaultPath, defaultExists });
            
            if (defaultExists) {
              const defBuffer = fs.readFileSync(defaultPath);
              formData.processed_logo = `data:image/jpeg;base64,${defBuffer.toString('base64')}`;
              log('INFO', 'Used default logo fallback', { base64Length: formData.processed_logo.length });
            } else {
              log('WARN', 'Default logo file also not found', { defaultPath });
            }
          }
        }
      } catch (imgErr) {
        log('ERROR', 'Failed to process logo to base64', { error: imgErr.message });
      }
    }

    // 4. Generate PDF with Playwright
    log('INFO', 'Getting browser instance for PDF generation');
    let browser;
    try {
      browser = await getBrowserInstance();
    } catch (browserError) {
      log('ERROR', 'Failed to get browser instance for PDF generation', { 
        error: browserError.message, 
        stack: browserError.stack,
        isRender: process.env.RENDER === 'true' || !!process.env.RENDER_SERVICE_NAME
      });
      throw new Error(`Failed to initialize browser for PDF generation: ${browserError.message}. This may be due to missing system dependencies or Playwright installation issues.`);
    }
    log('INFO', 'Creating new context');
    const context = await browser.newContext();
    log('INFO', 'Creating new page');
    const page = await context.newPage();
    log('INFO', 'Page created successfully');

    log('INFO', 'Setting page content', { contentLength: htmlContent.length });
    // Set base URL so relative paths (images, css, js) resolve correctly
    // On Render, we need to use the correct base URL
    let baseUrl = `http://localhost:${port}`;
    
    // If we're on Render, use the service URL
    if (process.env.RENDER === 'true' || process.env.RENDER_SERVICE_NAME) {
      // Use Render's internal service URL or construct from environment
      baseUrl = process.env.RENDER_SERVICE_URL || 
                process.env.RENDER_EXTERNAL_HOSTNAME || 
                `http://${process.env.RENDER_SERVICE_NAME}.onrender.com` ||
                `http://localhost:${port}`;
      log('INFO', 'Using Render-specific base URL', { baseUrl });
    }
    
    log('INFO', 'Using base URL for page content', { 
      baseUrl, 
      RENDER: process.env.RENDER, 
      port, 
      NODE_ENV: process.env.NODE_ENV,
      RENDER_SERVICE_NAME: process.env.RENDER_SERVICE_NAME,
      RENDER_SERVICE_URL: process.env.RENDER_SERVICE_URL,
      RENDER_EXTERNAL_HOSTNAME: process.env.RENDER_EXTERNAL_HOSTNAME
    });
    
    try {
      await page.setContent(htmlContent, {
        waitUntil: "networkidle",
        timeout: 30000, // Increase timeout for reliability
        baseUrl: baseUrl
      });
      log('INFO', 'Page content set successfully');
    } catch (setContentError) {
      log('ERROR', 'Failed to set page content', { 
        error: setContentError.message, 
        stack: setContentError.stack,
        contentLength: htmlContent.length
      });
      throw new Error(`Failed to set page content: ${setContentError.message}`);
    }
    log('INFO', 'Page content set successfully');

    // 5. Populate Form Data via DOM manipulation
    log('DEBUG', 'Populating form data', { dataKeys: Object.keys(formData), dataSample: Object.keys(formData).slice(0, 5) });
    
    log('DEBUG', 'Starting page evaluation');
    try {
      await page.evaluate((data) => {
        // A. Set Logo Immediately if present
        if (data.processed_logo) {
          const logoImg = document.getElementById('companyLogo');
          if (logoImg) {
            logoImg.src = data.processed_logo;
          }
        } else if (data.logo_select) {
          // Fallback to trying the URL if base64 failed
          const logoImg = document.getElementById('companyLogo');
          if (logoImg) logoImg.src = data.logo_select;
        }

        // B. Populate text/select/check inputs
        Object.entries(data).forEach(([name, value]) => {
          if (name === 'processed_logo') return; // skip our internal field

          const inputs = document.querySelectorAll(`[name="${name}"]`);
          inputs.forEach(input => {
            let shouldTriggerChange = false;

            if (input.tagName === 'SELECT') {
              const option = Array.from(input.options).find(o => o.value === value || o.text === value);
              if (option) {
                input.value = option.value;
                shouldTriggerChange = true;
              }
            } else if (input.type === 'checkbox' || input.type === 'radio') {
              if (String(value) === 'true' || String(value) === 'on' || value === input.value) {
                input.checked = true;
                shouldTriggerChange = true;
              }
            } else {
              input.value = value;
              input.setAttribute('value', value);
            }

            if (shouldTriggerChange) {
              input.dispatchEvent(new Event('change', { bubbles: true }));
            }
          });
          const textareas = document.querySelectorAll(`textarea[name="${name}"]`);
          textareas.forEach(ta => {
            ta.value = value;
            ta.textContent = value;
          });
        });
      }, formData);
      log('DEBUG', 'Page evaluation completed successfully');
    } catch (evalError) {
      log('ERROR', 'Failed during page evaluation', { 
        error: evalError.message, 
        stack: evalError.stack
      });
      throw new Error(`Failed during form data population: ${evalError.message}`);
    }

    log('INFO', 'Emulating print media');
    try {
      await page.emulateMedia({ media: 'print' });
      // Short wait is still good practice for layout reflows
      log('INFO', 'Waiting for timeout');
      await page.waitForTimeout(500);

      log('INFO', 'Generating PDF');
      const pdfBuffer = await page.pdf({
        format: "A4",
        printBackground: true,
        margin: { top: "10mm", bottom: "10mm", left: "10mm", right: "10mm" },
      });
      log('INFO', 'PDF generated successfully', { bufferSize: pdfBuffer.length });
      
      // Check if the buffer is valid
      if (!pdfBuffer || pdfBuffer.length === 0) {
        log('ERROR', 'Generated PDF buffer is invalid', { bufferSize: pdfBuffer?.length });
        throw new Error('Generated PDF buffer is invalid');
      }
      
      // Assign pdfBuffer to a variable accessible outside this block
      var finalPdfBuffer = pdfBuffer;
    } catch (pdfError) {
      log('ERROR', 'Failed during PDF generation', { 
        error: pdfError.message, 
        stack: pdfError.stack
      });
      throw new Error(`Failed during PDF generation: ${pdfError.message}`);
    }

    log('DEBUG', 'Closing context');
    await context.close();
    log('DEBUG', 'Context closed successfully');

    const filename = `${reportType}-${Date.now()}.pdf`;
    
    log('DEBUG', 'Setting response headers', { filename, contentType: "application/pdf" });

    res.set("Content-Type", "application/pdf");
    res.set("Content-Disposition", `attachment; filename="${filename}"`);
    
    log('DEBUG', 'Sending PDF response', { bufferSize: finalPdfBuffer.length });
    res.send(finalPdfBuffer);
    log('DEBUG', 'PDF response sent successfully');

    log('INFO', 'PDF exported successfully', { reportId, filename });

  } catch (err) {
    log('ERROR', 'PDF export failed', { 
      error: err.message, 
      stack: err.stack, 
      reportId: req.params.reportId,
      reportType: req.body?.reportType,
      // Add more debugging info
      errorMessage: err.toString(),
      errorName: err.name,
      // Check if db is still connected
      dbConnected: !!db?.serverConfig?.isConnected()
    });
    
    // Send more detailed error information in development
    if (process.env.NODE_ENV === 'development') {
      sendErrorResponse(res, 500, 'Failed to export PDF', `${err.name}: ${err.message}\n${err.stack}`);
    } else {
      sendErrorResponse(res, 500, 'Failed to export PDF', err.message);
    }
  }
});

// API: Delete Saved Report
app.delete("/api/delete-saved-report/:reportId", async (req, res) => {
  try {
    const reportId = req.params.reportId;

    if (!ObjectId.isValid(reportId)) {
      return sendErrorResponse(res, 400, 'Invalid report ID');
    }

    log('INFO', 'Delete saved report request', { reportId });

    const reportsCollection = db.collection('saved_reports');
    const result = await reportsCollection.deleteOne({ _id: new ObjectId(reportId) });

    if (result.deletedCount === 0) {
      return sendErrorResponse(res, 404, 'Report not found');
    }

    log('INFO', 'Report deleted successfully', { reportId });
    res.json({ success: true, message: 'Report deleted successfully' });

  } catch (err) {
    log('ERROR', 'Failed to delete report', { 
      error: err.message, 
      stack: err.stack,
      // Check if db is still connected
      dbConnected: !!db?.serverConfig?.isConnected()
    });
    sendErrorResponse(res, 500, 'Failed to delete report', err.message);
  }
});

// API: Update Admin Password
app.post("/api/update-password", authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.id;

    // Validation
    if (!currentPassword || !newPassword) {
      return sendErrorResponse(res, 400, 'Current password and new password are required');
    }

    if (newPassword.length < 6) {
      return sendErrorResponse(res, 400, 'New password must be at least 6 characters');
    }

    log('INFO', 'Password update request', { userId });

    // Get current user
    const usersCollection = db.collection('users');
    const user = await usersCollection.findOne({ _id: new ObjectId(userId) });

    if (!user) {
      return sendErrorResponse(res, 404, 'User not found');
    }

    // Verify current password
    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordValid) {
      log('WARN', 'Password update failed - incorrect current password', { userId });
      return sendErrorResponse(res, 401, 'Current password is incorrect');
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password
    await usersCollection.updateOne(
      { _id: new ObjectId(userId) },
      { $set: { password: hashedPassword, updatedAt: new Date() } }
    );

    log('INFO', 'Password updated successfully', { userId });
    res.json({ success: true, message: 'Password updated successfully' });

  } catch (err) {
    log('ERROR', 'Password update failed', { 
      error: err.message, 
      stack: err.stack,
      // Check if db is still connected
      dbConnected: !!db?.serverConfig?.isConnected()
    });
    sendErrorResponse(res, 500, 'Failed to update password', err.message);
  }
});

app.post("/submit-report", authMiddleware, async (req, res) => {
  // Accept either:
  // - reportType (string key like 'liquid_ir') OR
  // - folder (numeric 1..15)
  // If reportType provided, it determines the folder number using mapping.
  const { html, reportType, folder, reportTitle } = req.body;

  log('INFO', 'Report submission attempt', {
    reportType,
    folder,
    reportTitle,
    userId: req.user?.id
  });

  // Validate input
  const validationErrors = validateReportInput(html, reportType, folder, reportTitle);
  if (validationErrors.length > 0) {
    log('WARN', 'Report submission validation failed', {
      reportType,
      folder,
      errors: validationErrors,
      userId: req.user?.id
    });
    return sendErrorResponse(res, 400, validationErrors.join(', '));
  }

  // resolve folder number
  let folderNumber = null;
  if (reportType && reportTypeToFolder[reportType]) {
    folderNumber = reportTypeToFolder[reportType];
  } else if (typeof folder === "number" || (typeof folder === "string" && folder.trim() !== "")) {
    const f = parseInt(folder, 10);
    if (!isNaN(f) && f >= 1 && f <= 15) folderNumber = f;
  }

  if (!folderNumber) {
    log('WARN', 'Report submission failed - invalid folder', {
      reportType,
      folder,
      userId: req.user?.id
    });
    return sendErrorResponse(res, 400, "Missing or invalid reportType/folder (must map to 1-15)");
  }

  // Check cache first
  const cacheKey = generateCacheKey(html, reportType, folder, reportTitle);
  if (reportCache.has(cacheKey)) {
    const cachedEntry = reportCache.get(cacheKey);
    if (Date.now() - cachedEntry.timestamp < CACHE_TTL) {
      log('INFO', 'Report served from cache', {
        cacheKey,
        reportType,
        folder: folderNumber,
        userId: req.user?.id
      });
      return res.json({ fileId: cachedEntry.fileId, fromCache: true });
    } else {
      // Remove expired entry
      reportCache.delete(cacheKey);
    }
  }

  try {
    // Enhanced HTML sanitization
    let sanitizedHtml = html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "");
    // Remove other potentially dangerous tags
    sanitizedHtml = sanitizedHtml.replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, "");
    sanitizedHtml = sanitizedHtml.replace(/<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi, "");
    sanitizedHtml = sanitizedHtml.replace(/<embed\b[^<]*(?:(?!<\/embed>)<[^<]*)*<\/embed>/gi, "");
    // Remove on* event attributes
    sanitizedHtml = sanitizedHtml.replace(/\s(on\w+="[^"]*")/gi, "");

    // Reuse browser instance for better performance
    const browser = await getBrowserInstance();
    const context = await browser.newContext();
    const page = await context.newPage();

    const resolvedTitle = (reportTitle || reportType || "Report").toString().replace(/</g, "").slice(0, 150);

    const fullHtml = sanitizedHtml.includes("<html") ? sanitizedHtml : `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="UTF-8">
          <title>${resolvedTitle}</title>
          <style>
            html, body {
              margin: 0;
              padding: 0;
              font-family: 'Segoe UI', Arial, sans-serif;
              font-size: 12pt;
              color: #000;
            }
            input, textarea, select {
              font-family: 'Segoe UI', Arial, sans-serif;
              font-size: 12pt;
              color: #000;
              border: none;
            }
            table { border-collapse: collapse; width: 100%; }
            td, th { border: 1px solid #000; padding: 8px; word-wrap: break-word; white-space: pre-wrap; }
          </style>
        </head>
        <body>${sanitizedHtml}</body>
      </html>
    `;

    await page.setContent(fullHtml, { waitUntil: "networkidle" });
    await page.emulateMedia({ media: 'screen' });
    await page.waitForTimeout(500);

    const pdfBuffer = await page.pdf({
      format: "A4",
      printBackground: true,
      margin: { top: "20mm", bottom: "20mm", left: "15mm", right: "15mm" },
    });

    // Clean up context
    await context.close();

    // Choose filename — prefer the reportType key (if available), else fallback to sanitized title.
    const safeNameBase = (reportType && typeof reportType === "string" ? reportType : resolvedTitle.replace(/\s+/g, "_")).replace(/[^\w\-_.]/g, "");
    const filename = `${safeNameBase}-${Date.now()}.pdf`;

    const uploadStream = bucket.openUploadStream(filename, {
      metadata: { folder: folderNumber }
    });

    uploadStream.end(pdfBuffer, err => {
      if (err) {
        log('ERROR', 'PDF upload failed', {
          filename,
          folder: folderNumber,
          error: err.message,
          userId: req.user?.id
        });
        return sendErrorResponse(res, 500, "Failed to upload PDF", err.message);
      }

      log('INFO', 'PDF uploaded successfully', {
        fileId: uploadStream.id,
        filename,
        folder: folderNumber,
        userId: req.user?.id
      });

      // Add to cache
      if (reportCache.size < MAX_CACHE_SIZE) {
        reportCache.set(cacheKey, {
          fileId: uploadStream.id,
          timestamp: Date.now()
        });
        log('INFO', 'Report added to cache', {
          cacheKey,
          fileId: uploadStream.id,
          userId: req.user?.id
        });
      }

      console.log(`✅ PDF uploaded in Folder ${folderNumber}: ${filename}`);
      res.json({ fileId: uploadStream.id, fromCache: false });
    });

  } catch (err) {
    log('ERROR', 'PDF generation failed', {
      reportType,
      folder: folderNumber,
      error: err.message,
      userId: req.user?.id
    });
    sendErrorResponse(res, 500, "Failed to generate PDF", err.message);
  }
});

// Updated to support optional folder filter
app.get("/all-reports", authMiddleware, async (req, res) => {
  log('INFO', 'Fetching reports', { userId: req.user?.id, query: req.query });

  try {
    // Validate folder parameter
    let folder = req.query.folder;
    if (folder !== undefined) {
      folder = parseInt(folder);
      if (isNaN(folder) || folder < 1 || folder > 15) {
        log('WARN', 'Invalid folder parameter for report fetching', { folder, userId: req.user?.id });
        return sendErrorResponse(res, 400, "Folder must be between 1 and 15");
      }
    }

    const filter = !isNaN(folder) ? { "metadata.folder": folder } : {};

    const files = await db.collection(`${bucketName}.files`)
      .find(filter)
      .sort({ uploadDate: -1 })
      .toArray();

    const reportList = files.map(file => ({
      fileId: file._id,
      filename: file.filename,
      folder: file.metadata?.folder || null,
      uploadDate: file.uploadDate,
    }));

    log('INFO', 'Reports fetched successfully', {
      count: reportList.length,
      folder,
      userId: req.user?.id
    });
    res.json(reportList);
  } catch (err) {
    log('ERROR', 'Failed to fetch reports', { error: err.message, userId: req.user?.id });
    sendErrorResponse(res, 500, "Failed to fetch reports", err.message);
  }
});

app.get("/get-pdf/:fileId", async (req, res) => {
  log('INFO', 'PDF retrieval attempt', { fileId: req.params.fileId });

  try {
    // Validate fileId parameter
    if (!req.params.fileId || typeof req.params.fileId !== 'string') {
      log('WARN', 'Invalid file ID for PDF retrieval', { fileId: req.params.fileId });
      return sendErrorResponse(res, 400, "Invalid file ID");
    }

    // Validate ObjectId format
    if (!ObjectId.isValid(req.params.fileId)) {
      log('WARN', 'Invalid file ID format for PDF retrieval', { fileId: req.params.fileId });
      return sendErrorResponse(res, 400, "Invalid file ID format");
    }

    const fileId = new ObjectId(req.params.fileId);
    const downloadStream = bucket.openDownloadStream(fileId);

    res.set("Content-Type", "application/pdf");
    downloadStream.pipe(res);

    log('INFO', 'PDF retrieved successfully', { fileId: req.params.fileId });
  } catch (err) {
    log('ERROR', 'PDF retrieval failed', {
      fileId: req.params.fileId,
      error: err.message
    });
    sendErrorResponse(res, 500, "Failed to retrieve PDF", err.message);
  }
});

app.delete("/delete-report/:fileId", authMiddleware, checkRole('admin'), async (req, res) => {
  log('INFO', 'Report deletion attempt', {
    fileId: req.params.fileId,
    userId: req.user?.id
  });

  try {
    // Validate fileId parameter
    if (!req.params.fileId || typeof req.params.fileId !== 'string') {
      log('WARN', 'Invalid file ID for report deletion', {
        fileId: req.params.fileId,
        userId: req.user?.id
      });
      return sendErrorResponse(res, 400, "Invalid file ID");
    }

    // Validate ObjectId format
    if (!ObjectId.isValid(req.params.fileId)) {
      log('WARN', 'Invalid file ID format for report deletion', {
        fileId: req.params.fileId,
        userId: req.user?.id
      });
      return sendErrorResponse(res, 400, "Invalid file ID format");
    }

    const fileId = new ObjectId(req.params.fileId);
    await bucket.delete(fileId);

    log('INFO', 'Report deleted successfully', {
      fileId: req.params.fileId,
      userId: req.user?.id
    });
    console.log(`🗑️ Deleted report ID: ${fileId}`);
    res.json({ message: "Report deleted successfully" });
  } catch (err) {
    log('ERROR', 'Report deletion failed', {
      fileId: req.params.fileId,
      error: err.message,
      userId: req.user?.id
    });
    sendErrorResponse(res, 500, "Failed to delete report", err.message);
  }
});

// Add report update endpoint
app.put("/update-report/:fileId", authMiddleware, async (req, res) => {
  log('INFO', 'Report update attempt', {
    fileId: req.params.fileId,
    userId: req.user?.id
  });

  try {
    // Validate fileId parameter
    if (!req.params.fileId || typeof req.params.fileId !== 'string') {
      log('WARN', 'Invalid file ID for report update', {
        fileId: req.params.fileId,
        userId: req.user?.id
      });
      return sendErrorResponse(res, 400, "Invalid file ID");
    }

    // Validate ObjectId format
    if (!ObjectId.isValid(req.params.fileId)) {
      log('WARN', 'Invalid file ID format for report update', {
        fileId: req.params.fileId,
        userId: req.user?.id
      });
      return sendErrorResponse(res, 400, "Invalid file ID format");
    }

    const fileId = new ObjectId(req.params.fileId);
    const { html, reportType, folder, reportTitle } = req.body;

    // Validate input
    const validationErrors = validateReportInput(html, reportType, folder, reportTitle);
    if (validationErrors.length > 0) {
      log('WARN', 'Report update validation failed', {
        reportType,
        folder,
        errors: validationErrors,
        userId: req.user?.id
      });
      return sendErrorResponse(res, 400, validationErrors.join(', '));
    }

    // resolve folder number
    let folderNumber = null;
    if (reportType && reportTypeToFolder[reportType]) {
      folderNumber = reportTypeToFolder[reportType];
    } else if (typeof folder === "number" || (typeof folder === "string" && folder.trim() !== "")) {
      const f = parseInt(folder, 10);
      if (!isNaN(f) && f >= 1 && f <= 15) folderNumber = f;
    }

    if (!folderNumber) {
      log('WARN', 'Report update failed - invalid folder', {
        fileId: req.params.fileId,
        reportType,
        folder,
        userId: req.user?.id
      });
      return sendErrorResponse(res, 400, "Missing or invalid reportType/folder (must map to 1-15)");
    }

    // Check if file exists
    const filesCollection = db.collection(`${bucketName}.files`);
    const existingFile = await filesCollection.findOne({ _id: fileId });

    if (!existingFile) {
      log('WARN', 'Report update failed - file not found', {
        fileId: req.params.fileId,
        userId: req.user?.id
      });
      return sendErrorResponse(res, 404, "Report not found");
    }

    // Enhanced HTML sanitization
    let sanitizedHtml = html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "");
    // Remove other potentially dangerous tags
    sanitizedHtml = sanitizedHtml.replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, "");
    sanitizedHtml = sanitizedHtml.replace(/<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi, "");
    sanitizedHtml = sanitizedHtml.replace(/<embed\b[^<]*(?:(?!<\/embed>)<[^<]*)*<\/embed>/gi, "");
    // Remove on* event attributes
    sanitizedHtml = sanitizedHtml.replace(/\s(on\w+="[^"]*")/gi, "");

    // Reuse browser instance for better performance
    const browser = await getBrowserInstance();
    const context = await browser.newContext();
    const page = await context.newPage();

    const resolvedTitle = (reportTitle || reportType || "Report").toString().replace(/</g, "").slice(0, 150);

    const fullHtml = sanitizedHtml.includes("<html") ? sanitizedHtml : `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="UTF-8">
          <title>${resolvedTitle}</title>
          <style>
            html, body {
              margin: 0;
              padding: 0;
              font-family: 'Segoe UI', Arial, sans-serif;
              font-size: 12pt;
              color: #000;
            }
            input, textarea, select {
              font-family: 'Segoe UI', Arial, sans-serif;
              font-size: 12pt;
              color: #000;
              border: none;
            }
            table { border-collapse: collapse; width: 100%; }
            td, th { border: 1px solid #000; padding: 8px; word-wrap: break-word; white-space: pre-wrap; }
          </style>
        </head>
        <body>${sanitizedHtml}</body>
      </html>
    `;

    await page.setContent(fullHtml, { waitUntil: "networkidle" });
    await page.emulateMedia({ media: 'screen' });
    await page.waitForTimeout(500);

    const pdfBuffer = await page.pdf({
      format: "A4",
      printBackground: true,
      margin: { top: "20mm", bottom: "20mm", left: "15mm", right: "15mm" },
    });

    // Clean up context
    await context.close();

    // Delete the old file
    await bucket.delete(fileId);

    // Upload the updated file with the same name
    const uploadStream = bucket.openUploadStream(existingFile.filename, {
      metadata: { folder: folderNumber }
    });

    uploadStream.end(pdfBuffer, err => {
      if (err) {
        log('ERROR', 'PDF update failed', {
          fileId: req.params.fileId,
          filename: existingFile.filename,
          folder: folderNumber,
          error: err.message,
          userId: req.user?.id
        });
        return sendErrorResponse(res, 500, "Failed to update PDF", err.message);
      }

      log('INFO', 'PDF updated successfully', {
        oldFileId: req.params.fileId,
        newFileId: uploadStream.id,
        filename: existingFile.filename,
        folder: folderNumber,
        userId: req.user?.id
      });

      console.log(`✅ PDF updated in Folder ${folderNumber}: ${existingFile.filename}`);
      res.json({
        oldFileId: req.params.fileId,
        newFileId: uploadStream.id,
        message: "Report updated successfully"
      });
    });

  } catch (err) {
    log('ERROR', 'PDF update failed', {
      fileId: req.params.fileId,
      error: err.message,
      userId: req.user?.id
    });
    sendErrorResponse(res, 500, "Failed to update PDF", err.message);
  }
});

// Add search endpoint for reports
app.get("/search-reports", authMiddleware, async (req, res) => {
  log('INFO', 'Searching reports', { userId: req.user?.id, query: req.query });

  try {
    const { query, folder, startDate, endDate } = req.query;

    // Build filter object
    const filter = {};

    // Add folder filter if specified
    if (folder !== undefined) {
      const folderNum = parseInt(folder);
      if (!isNaN(folderNum) && folderNum >= 1 && folderNum <= 15) {
        filter["metadata.folder"] = folderNum;
      } else if (folder !== undefined) {
        log('WARN', 'Invalid folder parameter for report search', { folder, userId: req.user?.id });
        return sendErrorResponse(res, 400, "Folder must be between 1 and 15");
      }
    }

    // Add date range filters if specified
    if (startDate || endDate) {
      filter.uploadDate = {};

      if (startDate) {
        const start = new Date(startDate);
        if (isNaN(start.getTime())) {
          return sendErrorResponse(res, 400, "Invalid start date format");
        }
        filter.uploadDate.$gte = start;
      }

      if (endDate) {
        const end = new Date(endDate);
        if (isNaN(end.getTime())) {
          return sendErrorResponse(res, 400, "Invalid end date format");
        }
        filter.uploadDate.$lte = end;
      }
    }

    // Add text search if query is provided
    let files = [];
    if (query) {
      // First try to find exact filename matches
      const nameFilter = { ...filter, filename: { $regex: query, $options: 'i' } };
      files = await db.collection(`${bucketName}.files`)
        .find(nameFilter)
        .sort({ uploadDate: -1 })
        .toArray();

      // If no exact matches, try partial matches
      if (files.length === 0) {
        const partialFilter = { ...filter, filename: { $regex: query, $options: 'i' } };
        files = await db.collection(`${bucketName}.files`)
          .find(partialFilter)
          .sort({ uploadDate: -1 })
          .toArray();
      }
    } else {
      // No search query, just apply filters
      files = await db.collection(`${bucketName}.files`)
        .find(filter)
        .sort({ uploadDate: -1 })
        .toArray();
    }

    const reportList = files.map(file => ({
      fileId: file._id,
      filename: file.filename,
      folder: file.metadata?.folder || null,
      uploadDate: file.uploadDate,
    }));

    log('INFO', 'Reports search completed', {
      count: reportList.length,
      query,
      folder,
      userId: req.user?.id
    });

    res.json(reportList);
  } catch (err) {
    log('ERROR', 'Failed to search reports', { error: err.message, userId: req.user?.id });
    sendErrorResponse(res, 500, "Failed to search reports", err.message);
  }
});

// Add share report endpoint
app.post("/share-report/:fileId", authMiddleware, async (req, res) => {
  // ... (existing share logic if any, or placeholder)
  res.status(501).json({ error: "Not implemented" });
});

// --- Admin Console Routes ---

// Render Admin Console
app.get("/admin-console", (req, res) => {
  res.render("admin-console");
});

// API: List Users
app.get("/api/users", authMiddleware, checkRole('admin'), async (req, res) => {
  try {
    const users = await db.collection('users').find({}, { projection: { password: 0 } }).toArray();
    res.json(users);
  } catch (err) {
    sendErrorResponse(res, 500, "Failed to fetch users");
  }
});

// API: Create User
app.post("/api/users", authMiddleware, checkRole('admin'), async (req, res) => {
  const { username, password, role } = req.body;
  const errors = validateUserInput(username, password);
  if (errors.length > 0) return sendErrorResponse(res, 400, errors.join(', '));

  try {
    const existing = await db.collection('users').findOne({ username });
    if (existing) return sendErrorResponse(res, 400, "Username exists");

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.collection('users').insertOne({
      username,
      password: hashedPassword,
      role: role || 'user',
      createdAt: new Date()
    });

    log('INFO', 'User created by admin', { createdUser: username, adminId: req.user.id });
    res.status(201).json({ message: "User created" });
  } catch (err) {
    sendErrorResponse(res, 500, "Failed to create user");
  }
});

// API: Delete User
app.delete("/api/users/:id", authMiddleware, checkRole('admin'), async (req, res) => {
  try {
    const userId = req.params.id;
    // Prevent deleting self or main admin (optional check)
    if (userId === req.user.id) return sendErrorResponse(res, 400, "Cannot delete yourself");

    await db.collection('users').deleteOne({ _id: new ObjectId(userId) });
    log('WARN', 'User deleted by admin', { deletedUserId: userId, adminId: req.user.id });
    res.json({ message: "User deleted" });
  } catch (err) {
    sendErrorResponse(res, 500, "Failed to delete user");
  }
});

// API: Get Settings
app.get("/api/settings", authMiddleware, checkRole('admin'), (req, res) => {
  res.json({
    env: process.env.NODE_ENV || 'development',
    dbStatus: 'Connected',
    emailConfigured: !!(process.env.SMTP_HOST && process.env.SMTP_USER),
    rateLimit: process.env.RATE_LIMIT_MAX_REQUESTS || 10
  });
});

// API: Get Audit Logs
app.get("/api/audit-logs", authMiddleware, checkRole('admin'), async (req, res) => {
  log('INFO', 'Audit trail retrieval attempt', { userId: req.user?.id });

  try {
    // Check if user is admin
    if (req.user?.role !== 'admin') {
      log('WARN', 'Unauthorized audit trail access attempt', { userId: req.user?.id });
      return sendErrorResponse(res, 403, "Access denied. Admin privileges required.");
    }

    // Get query parameters for filtering
    const { level, userId, startDate, endDate, limit = 100 } = req.query;

    // Build filter object
    const filter = {};

    // Add level filter if specified
    if (level && ['ERROR', 'WARN', 'INFO', 'DEBUG'].includes(level)) {
      filter.level = level;
    }

    // Add user ID filter if specified
    if (userId) {
      filter.userId = userId;
    }

    // Add date range filters if specified
    if (startDate || endDate) {
      filter.timestamp = {};

      if (startDate) {
        const start = new Date(startDate);
        if (isNaN(start.getTime())) {
          return sendErrorResponse(res, 400, "Invalid start date format");
        }
        filter.timestamp.$gte = start;
      }

      if (endDate) {
        const end = new Date(endDate);
        if (isNaN(end.getTime())) {
          return sendErrorResponse(res, 400, "Invalid end date format");
        }
        filter.timestamp.$lte = end;
      }
    }

    // Retrieve audit logs
    const auditLogs = await db.collection(auditCollectionName)
      .find(filter)
      .sort({ timestamp: -1 })
      .limit(parseInt(limit) || 100)
      .toArray();

    log('INFO', 'Audit trail retrieved successfully', {
      count: auditLogs.length,
      userId: req.user?.id
    });

    res.json(auditLogs);
  } catch (err) {
    log('ERROR', 'Failed to retrieve audit trail', { error: err.message, userId: req.user?.id });
    sendErrorResponse(res, 500, "Failed to retrieve audit trail", err.message);
  }
});

// Add data backup endpoint
app.post("/backup", authMiddleware, async (req, res) => {
  log('INFO', 'Database backup attempt', { userId: req.user?.id });

  try {
    // Check if user is admin
    if (req.user?.role !== 'admin') {
      log('WARN', 'Unauthorized backup attempt', { userId: req.user?.id });
      return sendErrorResponse(res, 403, "Access denied. Admin privileges required.");
    }

    // Get current timestamp for backup naming
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupName = `backup-${timestamp}`;

    // Collections to backup (excluding system collections)
    const collectionsToBackup = [
      'users',
      'reports.files',
      'reports.chunks',
      auditCollectionName
    ];

    const backupData = {};

    // Backup each collection
    for (const collectionName of collectionsToBackup) {
      try {
        const collection = db.collection(collectionName);
        const documents = await collection.find({}).toArray();
        backupData[collectionName] = documents;
        log('INFO', `Backed up collection: ${collectionName}`, {
          count: documents.length,
          userId: req.user?.id
        });
      } catch (collectionErr) {
        log('WARN', `Failed to backup collection: ${collectionName}`, {
          error: collectionErr.message,
          userId: req.user?.id
        });
        // Continue with other collections even if one fails
      }
    }

    // Create backup metadata
    const backupMetadata = {
      name: backupName,
      timestamp: new Date(),
      collections: Object.keys(backupData),
      userId: req.user?.id
    };

    // Store backup metadata in a special collection
    await db.collection('backups').insertOne(backupMetadata);

    log('INFO', 'Database backup completed successfully', {
      backupName,
      collections: Object.keys(backupData),
      userId: req.user?.id
    });

    // Return backup data as JSON
    res.json({
      message: "Backup completed successfully",
      backupName,
      backupData,
      metadata: backupMetadata
    });
  } catch (err) {
    log('ERROR', 'Failed to create database backup', { error: err.message, userId: req.user?.id });
    sendErrorResponse(res, 500, "Failed to create database backup", err.message);
  }
});

// Add endpoint to list available backups
app.get("/backups", authMiddleware, async (req, res) => {
  log('INFO', 'Backup list retrieval attempt', { userId: req.user?.id });

  try {
    // Check if user is admin
    if (req.user?.role !== 'admin') {
      log('WARN', 'Unauthorized backup list access attempt', { userId: req.user?.id });
      return sendErrorResponse(res, 403, "Access denied. Admin privileges required.");
    }

    // Retrieve backup metadata
    const backups = await db.collection('backups')
      .find({})
      .sort({ timestamp: -1 })
      .toArray();

    log('INFO', 'Backup list retrieved successfully', {
      count: backups.length,
      userId: req.user?.id
    });

    res.json(backups);
  } catch (err) {
    log('ERROR', 'Failed to retrieve backup list', { error: err.message, userId: req.user?.id });
    sendErrorResponse(res, 500, "Failed to retrieve backup list", err.message);
  }
});

// Add endpoint to restore from backup
app.post("/restore/:backupId", authMiddleware, async (req, res) => {
  log('INFO', 'Database restore attempt', {
    backupId: req.params.backupId,
    userId: req.user?.id
  });

  try {
    // Check if user is admin
    if (req.user?.role !== 'admin') {
      log('WARN', 'Unauthorized restore attempt', { userId: req.user?.id });
      return sendErrorResponse(res, 403, "Access denied. Admin privileges required.");
    }

    // Validate backupId parameter
    if (!req.params.backupId || typeof req.params.backupId !== 'string') {
      log('WARN', 'Invalid backup ID for restore', {
        backupId: req.params.backupId,
        userId: req.user?.id
      });
      return sendErrorResponse(res, 400, "Invalid backup ID");
    }

    // Find the backup metadata
    const backupMetadata = await db.collection('backups').findOne({
      _id: new ObjectId(req.params.backupId)
    });

    if (!backupMetadata) {
      log('WARN', 'Backup not found for restore', {
        backupId: req.params.backupId,
        userId: req.user?.id
      });
      return sendErrorResponse(res, 404, "Backup not found");
    }

    // In a real implementation, you would restore the data here
    // For this project, we'll just simulate the restore process
    log('INFO', 'Database restore simulation completed', {
      backupName: backupMetadata.name,
      userId: req.user?.id
    });

    res.json({
      message: "Restore simulation completed successfully",
      backupName: backupMetadata.name,
      restoredAt: new Date()
    });
  } catch (err) {
    log('ERROR', 'Failed to restore database', {
      backupId: req.params.backupId,
      error: err.message,
      userId: req.user?.id
    });
    sendErrorResponse(res, 500, "Failed to restore database", err.message);
  }
});

// Endpoint to export saved report to PDF
// This route was removed to eliminate duplicate route definitions
// The primary implementation is at lines 655-845

// Health check endpoint
app.get("/health", async (req, res) => {
  try {
    // Check database connection
    await db.command({ ping: 1 });

    // Check if required collections exist
    const collections = await db.listCollections().toArray();
    const collectionNames = collections.map(c => c.name);

    // Check if Playwright is working
    let playwrightWorking = false;
    let playwrightError = null;
    try {
      log('DEBUG', 'Testing Playwright in health check');
      // Check if we're running on Render
      const isRender = process.env.RENDER === 'true' || !!process.env.RENDER_SERVICE_NAME;
      
      if (isRender) {
        log('INFO', 'Running on Render, using simplified browser launch options for health check');
        // Simplified launch options for Render environment
        try {
          const browser = await playwright.chromium.launch({
            headless: true
          });
          await browser.close();
        } catch (renderLaunchError) {
          log('WARN', 'Standard Render launch failed in health check, trying without specific options', { error: renderLaunchError.message });
          // Fallback to basic launch
          try {
            const browser = await playwright.chromium.launch({
              headless: true
            });
            await browser.close();
          } catch (fallbackError) {
            log('ERROR', 'All Render launch attempts failed in health check', { 
              standardError: renderLaunchError.message,
              fallbackError: fallbackError.message
            });
            throw new Error(`Failed to launch browser on Render: ${renderLaunchError.message}. Fallback also failed: ${fallbackError.message}`);
          }
        }
      } else {
        // Standard launch options for local development
        try {
          const browser = await playwright.chromium.launch({
            headless: true,
            args: [
              '--no-sandbox', 
              '--disable-setuid-sandbox',
              '--disable-dev-shm-usage',
              '--disable-gpu',
              '--no-zygote'
            ]
          });
          await browser.close();
        } catch (standardLaunchError) {
          log('ERROR', 'Standard launch failed in health check', { error: standardLaunchError.message });
          throw new Error(`Failed to launch browser with standard options: ${standardLaunchError.message}`);
        }
      }
      playwrightWorking = true;
      log('DEBUG', 'Playwright test successful');
    } catch (playwrightErr) {
      log('WARN', 'Playwright health check failed', { error: playwrightErr.message, stack: playwrightErr.stack });
      playwrightError = playwrightErr.message;
    }

    res.json({
      status: "healthy",
      database: "connected",
      collections: collectionNames,
      playwright: playwrightWorking ? "working" : "failed",
      playwrightError: playwrightError,
      timestamp: new Date()
    });
  } catch (err) {
    log('ERROR', 'Health check failed', { error: err.message, stack: err.stack });
    sendErrorResponse(res, 500, "Health check failed", err.message);
  }
});

// Only start the server if this file is run directly (not imported)
if (require.main === module) {
  const server = app.listen(port, () => {
    console.log(`🚀 Server running at http://localhost:${port}`);
    log('INFO', 'Server started successfully', { port });
  });

  // Graceful shutdown for the HTTP server
  process.on('SIGTERM', () => {
    log('INFO', 'SIGTERM received, shutting down gracefully');
    server.close(() => {
      log('INFO', 'Process terminated');
    });
  });
  
  process.on('SIGINT', () => {
    log('INFO', 'SIGINT received, shutting down gracefully');
    server.close(() => {
      log('INFO', 'Process terminated');
      process.exit(0);
    });
  });
}

// Export the app for testing
module.exports = app;

// Simple in-memory cache for report generation
const reportCache = new Map();
const CACHE_TTL = process.env.CACHE_TTL || 30 * 60 * 1000; // 30 minutes
const MAX_CACHE_SIZE = process.env.MAX_CACHE_SIZE || 100; // Maximum number of cached items

// Cache cleanup interval
setInterval(() => {
  const now = Date.now();
  for (const [key, cacheEntry] of reportCache.entries()) {
    if (now - cacheEntry.timestamp > CACHE_TTL) {
      reportCache.delete(key);
    }
  }
}, 60000); // Check every minute

// Generate cache key based on report content
function generateCacheKey(html, reportType, folder, reportTitle) {
  // Create a hash of the content to use as cache key
  const crypto = require('crypto');
  const content = `${html}|${reportType}|${folder}|${reportTitle}`;
  return crypto.createHash('md5').update(content).digest('hex');

}
