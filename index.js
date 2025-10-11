require('dotenv').config();
const express = require('express');
const cors = require('cors');
const connectDB = require('./config/db');
const authRoutes = require('./routes/auth');
const auditRoutes = require('./routes/audit');
const healthRoutes = require('./routes/health');
const errorHandler = require('./middleware/errorHandler');
const { apiLimiter } = require('./middleware/rateLimiter');
const requestLogger = require('./middleware/requestLogger');
const logger = require('./config/logger');
const healthService = require('./services/healthService');
const CleanupJobs = require('./jobs/cleanupJobs');

// Connect to database
connectDB();

const app = express();

// Initialize health service
healthService;

// Initialize cleanup jobs
CleanupJobs.initialize();

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Request logging
app.use(requestLogger);

// Rate limiting
app.use('/api/', apiLimiter);

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/audit', auditRoutes);
app.use('/api/health', healthRoutes);

// Legacy health check endpoint (redirect to new endpoint)
app.get('/health', (req, res) => {
  res.redirect('/api/health');
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

// Error handling middleware (must be last)
app.use(errorHandler);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  logger.info(`🚀 Auth Service running on port ${PORT}`);
  logger.info(`📊 Health check: http://localhost:${PORT}/api/health`);
  logger.info(`🔐 API Base URL: http://localhost:${PORT}/api/auth`);
  logger.info(`📋 Audit API: http://localhost:${PORT}/api/audit`);
  logger.info(`🏥 Health API: http://localhost:${PORT}/api/health`);
});
