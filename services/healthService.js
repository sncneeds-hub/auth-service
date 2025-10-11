const mongoose = require('mongoose');
const logger = require('../config/logger');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');

class HealthService {
  constructor() {
    this.healthChecks = new Map();
    this.metrics = {
      startTime: Date.now(),
      requestCount: 0,
      errorCount: 0,
      lastHealthCheck: null,
      dbConnectionStatus: 'unknown',
      memoryUsage: process.memoryUsage(),
      uptime: 0
    };
    
    this.initializeHealthChecks();
    this.startPeriodicChecks();
  }

  initializeHealthChecks() {
    // Database connectivity check
    this.healthChecks.set('database', {
      name: 'Database Connection',
      check: this.checkDatabase.bind(this),
      critical: true,
      timeout: 5000
    });

    // Memory usage check
    this.healthChecks.set('memory', {
      name: 'Memory Usage',
      check: this.checkMemory.bind(this),
      critical: false,
      timeout: 1000
    });

    // Disk space check (if applicable)
    this.healthChecks.set('disk', {
      name: 'Disk Space',
      check: this.checkDiskSpace.bind(this),
      critical: false,
      timeout: 2000
    });

    // External dependencies check
    this.healthChecks.set('dependencies', {
      name: 'External Dependencies',
      check: this.checkDependencies.bind(this),
      critical: false,
      timeout: 10000
    });
  }

  async checkDatabase() {
    try {
      const start = Date.now();
      
      // Check connection state
      if (mongoose.connection.readyState !== 1) {
        throw new Error('Database not connected');
      }

      // Perform a simple query to test responsiveness
      await User.findOne().limit(1).lean();
      
      const responseTime = Date.now() - start;
      this.metrics.dbConnectionStatus = 'connected';
      
      return {
        status: 'healthy',
        responseTime: `${responseTime}ms`,
        details: {
          state: mongoose.connection.readyState,
          host: mongoose.connection.host,
          name: mongoose.connection.name
        }
      };
    } catch (error) {
      this.metrics.dbConnectionStatus = 'error';
      logger.error('Database health check failed:', error);
      
      return {
        status: 'unhealthy',
        error: error.message,
        details: {
          state: mongoose.connection.readyState
        }
      };
    }
  }

  async checkMemory() {
    try {
      const memUsage = process.memoryUsage();
      this.metrics.memoryUsage = memUsage;
      
      // Convert bytes to MB
      const memoryMB = {
        rss: Math.round(memUsage.rss / 1024 / 1024),
        heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024),
        heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024),
        external: Math.round(memUsage.external / 1024 / 1024)
      };

      // Check if memory usage is concerning (>500MB heap used)
      const isHealthy = memoryMB.heapUsed < 500;
      
      return {
        status: isHealthy ? 'healthy' : 'warning',
        details: {
          ...memoryMB,
          unit: 'MB'
        }
      };
    } catch (error) {
      logger.error('Memory health check failed:', error);
      return {
        status: 'unhealthy',
        error: error.message
      };
    }
  }

  async checkDiskSpace() {
    try {
      // This is a simplified check - in production, you might want to use a library like 'node-disk-info'
      const fs = require('fs').promises;
      const stats = await fs.stat('./');
      
      return {
        status: 'healthy',
        details: {
          message: 'Disk space check not implemented - placeholder'
        }
      };
    } catch (error) {
      logger.error('Disk space health check failed:', error);
      return {
        status: 'warning',
        error: error.message
      };
    }
  }

  async checkDependencies() {
    const dependencies = [];
    
    try {
      // Check email service (if configured)
      if (process.env.SMTP_HOST) {
        const emailCheck = await this.checkEmailService();
        dependencies.push({
          name: 'Email Service',
          ...emailCheck
        });
      }

      // Check Redis (if configured)
      if (process.env.REDIS_URL) {
        const redisCheck = await this.checkRedisService();
        dependencies.push({
          name: 'Redis Cache',
          ...redisCheck
        });
      }

      const allHealthy = dependencies.every(dep => dep.status === 'healthy');
      
      return {
        status: allHealthy ? 'healthy' : 'warning',
        details: { dependencies }
      };
    } catch (error) {
      logger.error('Dependencies health check failed:', error);
      return {
        status: 'unhealthy',
        error: error.message
      };
    }
  }

  async checkEmailService() {
    try {
      // Simple check - try to create transporter
      const nodemailer = require('nodemailer');
      const transporter = nodemailer.createTransporter({
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT || 587,
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      });

      await transporter.verify();
      
      return {
        status: 'healthy',
        details: { host: process.env.SMTP_HOST }
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        error: error.message
      };
    }
  }

  async checkRedisService() {
    try {
      // Placeholder for Redis check
      return {
        status: 'healthy',
        details: { message: 'Redis check not implemented' }
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        error: error.message
      };
    }
  }

  async performHealthCheck() {
    const results = {};
    const start = Date.now();
    
    try {
      // Run all health checks
      for (const [key, healthCheck] of this.healthChecks) {
        try {
          const checkPromise = healthCheck.check();
          const timeoutPromise = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Health check timeout')), healthCheck.timeout)
          );
          
          results[key] = await Promise.race([checkPromise, timeoutPromise]);
        } catch (error) {
          results[key] = {
            status: 'unhealthy',
            error: error.message
          };
        }
      }

      // Update metrics
      this.metrics.lastHealthCheck = new Date();
      this.metrics.uptime = Date.now() - this.metrics.startTime;
      
      // Determine overall health
      const criticalChecks = Array.from(this.healthChecks.entries())
        .filter(([_, check]) => check.critical)
        .map(([key, _]) => key);
      
      const criticalFailures = criticalChecks.filter(key => 
        results[key]?.status === 'unhealthy'
      );
      
      const overallStatus = criticalFailures.length > 0 ? 'unhealthy' : 
        Object.values(results).some(r => r.status === 'warning') ? 'warning' : 'healthy';

      const healthReport = {
        status: overallStatus,
        timestamp: new Date().toISOString(),
        uptime: this.formatUptime(this.metrics.uptime),
        version: process.env.npm_package_version || '1.0.0',
        environment: process.env.NODE_ENV || 'development',
        checks: results,
        metrics: {
          requestCount: this.metrics.requestCount,
          errorCount: this.metrics.errorCount,
          errorRate: this.metrics.requestCount > 0 ? 
            ((this.metrics.errorCount / this.metrics.requestCount) * 100).toFixed(2) + '%' : '0%',
          memoryUsage: {
            heapUsed: Math.round(this.metrics.memoryUsage.heapUsed / 1024 / 1024) + 'MB',
            heapTotal: Math.round(this.metrics.memoryUsage.heapTotal / 1024 / 1024) + 'MB'
          }
        },
        responseTime: `${Date.now() - start}ms`
      };

      // Log health status
      if (overallStatus === 'unhealthy') {
        logger.error('Health check failed', { healthReport });
      } else if (overallStatus === 'warning') {
        logger.warn('Health check warnings detected', { healthReport });
      } else {
        logger.debug('Health check passed', { status: overallStatus });
      }

      return healthReport;
    } catch (error) {
      logger.error('Health check system error:', error);
      return {
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        error: 'Health check system failure',
        details: error.message
      };
    }
  }

  startPeriodicChecks() {
    // Run health checks every 30 seconds
    setInterval(async () => {
      try {
        await this.performHealthCheck();
      } catch (error) {
        logger.error('Periodic health check failed:', error);
      }
    }, 30000);

    logger.info('Periodic health checks started (30s interval)');
  }

  incrementRequestCount() {
    this.metrics.requestCount++;
  }

  incrementErrorCount() {
    this.metrics.errorCount++;
  }

  formatUptime(milliseconds) {
    const seconds = Math.floor(milliseconds / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) return `${days}d ${hours % 24}h ${minutes % 60}m`;
    if (hours > 0) return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
  }

  // Get system metrics for monitoring
  async getMetrics() {
    try {
      const userStats = await User.aggregate([
        {
          $group: {
            _id: '$role',
            count: { $sum: 1 },
            verified: { $sum: { $cond: ['$isVerified', 1, 0] } },
            approved: { $sum: { $cond: ['$approvedByAdmin', 1, 0] } }
          }
        }
      ]);

      const recentAuditLogs = await AuditLog.countDocuments({
        timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
      });

      return {
        system: {
          uptime: this.formatUptime(this.metrics.uptime),
          requestCount: this.metrics.requestCount,
          errorCount: this.metrics.errorCount,
          errorRate: this.metrics.requestCount > 0 ? 
            ((this.metrics.errorCount / this.metrics.requestCount) * 100).toFixed(2) + '%' : '0%',
          memoryUsage: this.metrics.memoryUsage
        },
        database: {
          connectionStatus: this.metrics.dbConnectionStatus,
          userStats,
          recentAuditLogs
        },
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error('Failed to get metrics:', error);
      throw error;
    }
  }
}

module.exports = new HealthService();