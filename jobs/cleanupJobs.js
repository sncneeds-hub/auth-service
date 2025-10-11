const cron = require('node-cron');
const RefreshToken = require('../models/RefreshToken');
const UserSecurity = require('../models/UserSecurity');
const AuditLog = require('../models/AuditLog');
const TokenUtils = require('../utils/tokenUtils');
const logger = require('../config/logger');

class CleanupJobs {
  static initialize() {
    // Cleanup expired refresh tokens every hour
    cron.schedule('0 * * * *', async () => {
      try {
        logger.info('Starting expired refresh tokens cleanup');
        const deletedCount = await TokenUtils.cleanupExpiredTokens();
        logger.info(`Cleanup completed: ${deletedCount} expired tokens removed`);
      } catch (error) {
        logger.error('Expired tokens cleanup failed:', error);
      }
    });

    // Cleanup old security events every day at 2 AM
    cron.schedule('0 2 * * *', async () => {
      try {
        logger.info('Starting old security events cleanup');
        await UserSecurity.cleanupOldEvents(90); // Keep 90 days
        logger.info('Security events cleanup completed');
      } catch (error) {
        logger.error('Security events cleanup failed:', error);
      }
    });

    // Cleanup old audit logs every day at 3 AM
    cron.schedule('0 3 * * *', async () => {
      try {
        logger.info('Starting old audit logs cleanup');
        const cutoffDate = new Date(Date.now() - (365 * 24 * 60 * 60 * 1000)); // 1 year
        const result = await AuditLog.deleteMany({
          timestamp: { $lt: cutoffDate }
        });
        logger.info(`Audit logs cleanup completed: ${result.deletedCount} logs removed`);
      } catch (error) {
        logger.error('Audit logs cleanup failed:', error);
      }
    });

    // Auto-unlock accounts every 5 minutes
    cron.schedule('*/5 * * * *', async () => {
      try {
        const now = new Date();
        const lockedUsers = await UserSecurity.find({
          isLocked: true,
          lockedUntil: { $lte: now }
        });

        for (const userSecurity of lockedUsers) {
          userSecurity.unlockAccount();
          await userSecurity.save();
          
          logger.info('Account auto-unlocked', {
            userId: userSecurity.userId,
            userEmail: userSecurity.userEmail
          });
        }

        if (lockedUsers.length > 0) {
          logger.info(`Auto-unlocked ${lockedUsers.length} accounts`);
        }
      } catch (error) {
        logger.error('Account auto-unlock failed:', error);
      }
    });

    // Generate daily statistics every day at 1 AM
    cron.schedule('0 1 * * *', async () => {
      try {
        logger.info('Generating daily statistics');
        
        const tokenStats = await TokenUtils.getTokenStatistics();
        const userCount = await require('../models/User').countDocuments();
        const auditCount = await AuditLog.countDocuments({
          timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
        });

        logger.info('Daily statistics', {
          users: userCount,
          tokens: tokenStats,
          auditLogs: auditCount,
          date: new Date().toISOString().split('T')[0]
        });
      } catch (error) {
        logger.error('Daily statistics generation failed:', error);
      }
    });

    logger.info('Cleanup jobs initialized');
  }
}

module.exports = CleanupJobs;