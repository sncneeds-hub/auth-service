const express = require('express');
const healthService = require('../services/healthService');
const { authenticate, authorize } = require('../middleware/auth');
const logger = require('../config/logger');

const router = express.Router();

// @route   GET /api/health
// @desc    Basic health check endpoint
// @access  Public
router.get('/', async (req, res) => {
  try {
    healthService.incrementRequestCount();
    
    const healthReport = await healthService.performHealthCheck();
    
    // Return appropriate HTTP status based on health
    const statusCode = healthReport.status === 'healthy' ? 200 : 
                      healthReport.status === 'warning' ? 200 : 503;
    
    res.status(statusCode).json({
      success: healthReport.status !== 'unhealthy',
      ...healthReport
    });
  } catch (error) {
    healthService.incrementErrorCount();
    logger.error('Health check endpoint error:', error);
    
    res.status(503).json({
      success: false,
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: 'Health check failed',
      message: 'Unable to perform health check'
    });
  }
});

// @route   GET /api/health/detailed
// @desc    Detailed health check with all metrics
// @access  Private (Admin only)
router.get('/detailed', authenticate, authorize('admin'), async (req, res) => {
  try {
    healthService.incrementRequestCount();
    
    const [healthReport, metrics] = await Promise.all([
      healthService.performHealthCheck(),
      healthService.getMetrics()
    ]);
    
    const detailedReport = {
      ...healthReport,
      metrics: {
        ...healthReport.metrics,
        ...metrics
      }
    };
    
    const statusCode = healthReport.status === 'healthy' ? 200 : 
                      healthReport.status === 'warning' ? 200 : 503;
    
    res.status(statusCode).json({
      success: healthReport.status !== 'unhealthy',
      ...detailedReport
    });
  } catch (error) {
    healthService.incrementErrorCount();
    logger.error('Detailed health check endpoint error:', error);
    
    res.status(503).json({
      success: false,
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: 'Detailed health check failed',
      message: error.message
    });
  }
});

// @route   GET /api/health/metrics
// @desc    Get system metrics
// @access  Private (Admin only)
router.get('/metrics', authenticate, authorize('admin'), async (req, res) => {
  try {
    healthService.incrementRequestCount();
    
    const metrics = await healthService.getMetrics();
    
    res.json({
      success: true,
      data: metrics
    });
  } catch (error) {
    healthService.incrementErrorCount();
    logger.error('Metrics endpoint error:', error);
    
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve metrics',
      error: error.message
    });
  }
});

// @route   GET /api/health/ready
// @desc    Readiness probe for Kubernetes/Docker
// @access  Public
router.get('/ready', async (req, res) => {
  try {
    // Quick readiness check - just verify database connection
    const healthReport = await healthService.performHealthCheck();
    const dbCheck = healthReport.checks?.database;
    
    if (dbCheck?.status === 'healthy') {
      res.status(200).json({
        success: true,
        status: 'ready',
        timestamp: new Date().toISOString()
      });
    } else {
      res.status(503).json({
        success: false,
        status: 'not ready',
        timestamp: new Date().toISOString(),
        reason: 'Database not available'
      });
    }
  } catch (error) {
    logger.error('Readiness check error:', error);
    res.status(503).json({
      success: false,
      status: 'not ready',
      timestamp: new Date().toISOString(),
      error: error.message
    });
  }
});

// @route   GET /api/health/live
// @desc    Liveness probe for Kubernetes/Docker
// @access  Public
router.get('/live', (req, res) => {
  // Simple liveness check - if the server can respond, it's alive
  res.status(200).json({
    success: true,
    status: 'alive',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

module.exports = router;