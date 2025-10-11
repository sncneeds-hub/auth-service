const express = require('express');
const AuditLog = require('../models/AuditLog');
const { authenticate, authorize } = require('../middleware/auth');
const { auditLoggers } = require('../middleware/auditLogger');
const logger = require('../config/logger');

const router = express.Router();

// @route   GET /api/audit/logs
// @desc    Get audit logs (Admin only)
// @access  Private (Admin only)
router.get('/logs', 
  authenticate, 
  authorize('admin'),
  auditLoggers.profileUpdate,
  async (req, res) => {
    try {
      const {
        page = 1,
        limit = 50,
        userId,
        action,
        success,
        startDate,
        endDate,
        ipAddress
      } = req.query;

      // Build filter object
      const filter = {};
      if (userId) filter.userId = userId;
      if (action) filter.action = action;
      if (success !== undefined) filter.success = success === 'true';
      if (ipAddress) filter.ipAddress = ipAddress;
      
      if (startDate || endDate) {
        filter.timestamp = {};
        if (startDate) filter.timestamp.$gte = new Date(startDate);
        if (endDate) filter.timestamp.$lte = new Date(endDate);
      }

      const logs = await AuditLog.find(filter)
        .populate('userId', 'email role')
        .sort({ timestamp: -1 })
        .limit(limit * 1)
        .skip((page - 1) * limit)
        .lean();

      const total = await AuditLog.countDocuments(filter);

      res.json({
        success: true,
        data: {
          logs,
          pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total,
            pages: Math.ceil(total / limit)
          }
        }
      });

    } catch (error) {
      logger.error('Get audit logs error:', error);
      res.status(500).json({
        success: false,
        message: 'Server error while fetching audit logs'
      });
    }
  }
);

// @route   GET /api/audit/user/:userId
// @desc    Get user activity logs
// @access  Private (Admin or own user)
router.get('/user/:userId',
  authenticate,
  auditLoggers.profileUpdate,
  async (req, res) => {
    try {
      const { userId } = req.params;
      
      // Check if user is admin or requesting their own logs
      if (req.user.role !== 'admin' && req.user._id.toString() !== userId) {
        return res.status(403).json({
          success: false,
          message: 'Access denied. You can only view your own activity logs.'
        });
      }

      const options = {
        page: req.query.page,
        limit: req.query.limit,
        action: req.query.action,
        startDate: req.query.startDate,
        endDate: req.query.endDate,
        success: req.query.success
      };

      const result = await AuditLog.getUserActivity(userId, options);

      res.json({
        success: true,
        data: result
      });

    } catch (error) {
      logger.error('Get user activity error:', error);
      res.status(500).json({
        success: false,
        message: 'Server error while fetching user activity'
      });
    }
  }
);

// @route   GET /api/audit/security
// @desc    Get security events (Admin only)
// @access  Private (Admin only)
router.get('/security',
  authenticate,
  authorize('admin'),
  auditLoggers.profileUpdate,
  async (req, res) => {
    try {
      const options = {
        page: req.query.page,
        limit: req.query.limit,
        hours: req.query.hours
      };

      const result = await AuditLog.getSecurityEvents(options);

      res.json({
        success: true,
        data: result
      });

    } catch (error) {
      logger.error('Get security events error:', error);
      res.status(500).json({
        success: false,
        message: 'Server error while fetching security events'
      });
    }
  }
);

// @route   GET /api/audit/stats
// @desc    Get audit statistics (Admin only)
// @access  Private (Admin only)
router.get('/stats',
  authenticate,
  authorize('admin'),
  auditLoggers.profileUpdate,
  async (req, res) => {
    try {
      const { days = 7 } = req.query;
      const startDate = new Date(Date.now() - (days * 24 * 60 * 60 * 1000));

      // Get total logs count
      const totalLogs = await AuditLog.countDocuments({
        timestamp: { $gte: startDate }
      });

      // Get success/failure counts
      const successCount = await AuditLog.countDocuments({
        timestamp: { $gte: startDate },
        success: true
      });

      const failureCount = await AuditLog.countDocuments({
        timestamp: { $gte: startDate },
        success: false
      });

      // Get top actions
      const topActions = await AuditLog.aggregate([
        { $match: { timestamp: { $gte: startDate } } },
        { $group: { _id: '$action', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ]);

      // Get top IP addresses
      const topIPs = await AuditLog.aggregate([
        { $match: { timestamp: { $gte: startDate } } },
        { $group: { _id: '$ipAddress', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ]);

      // Get daily activity
      const dailyActivity = await AuditLog.aggregate([
        { $match: { timestamp: { $gte: startDate } } },
        {
          $group: {
            _id: {
              $dateToString: { format: '%Y-%m-%d', date: '$timestamp' }
            },
            count: { $sum: 1 },
            successCount: {
              $sum: { $cond: [{ $eq: ['$success', true] }, 1, 0] }
            },
            failureCount: {
              $sum: { $cond: [{ $eq: ['$success', false] }, 1, 0] }
            }
          }
        },
        { $sort: { _id: 1 } }
      ]);

      res.json({
        success: true,
        data: {
          summary: {
            totalLogs,
            successCount,
            failureCount,
            successRate: totalLogs > 0 ? ((successCount / totalLogs) * 100).toFixed(2) : 0
          },
          topActions,
          topIPs,
          dailyActivity,
          period: {
            days: parseInt(days),
            startDate,
            endDate: new Date()
          }
        }
      });

    } catch (error) {
      logger.error('Get audit stats error:', error);
      res.status(500).json({
        success: false,
        message: 'Server error while fetching audit statistics'
      });
    }
  }
);

module.exports = router;