const AuditLog = require('../models/AuditLog');
const logger = require('../config/logger');

// Helper function to get client IP
const getClientIP = (req) => {
  return req.ip || 
         req.connection.remoteAddress || 
         req.socket.remoteAddress ||
         (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
         req.headers['x-forwarded-for']?.split(',')[0] ||
         req.headers['x-real-ip'] ||
         'unknown';
};

// Helper function to sanitize sensitive data
const sanitizeDetails = (details) => {
  const sanitized = { ...details };
  
  // Remove sensitive fields
  const sensitiveFields = [
    'password', 'passwordHash', 'token', 'refreshToken',
    'verificationToken', 'resetPasswordToken', 'secret'
  ];
  
  sensitiveFields.forEach(field => {
    if (sanitized[field]) {
      sanitized[field] = '[REDACTED]';
    }
  });
  
  return sanitized;
};

// Audit logging middleware
const auditLogger = (action, options = {}) => {
  return async (req, res, next) => {
    const startTime = Date.now();
    
    // Store original res.json to capture response
    const originalJson = res.json;
    let responseData = null;
    let statusCode = null;

    res.json = function(data) {
      responseData = data;
      statusCode = res.statusCode;
      return originalJson.call(this, data);
    };

    // Continue with the request
    res.on('finish', async () => {
      try {
        const endTime = Date.now();
        const duration = endTime - startTime;

        // Determine if the request was successful
        const success = statusCode >= 200 && statusCode < 400;
        
        // Extract user information
        const userId = req.user?._id || null;
        const userEmail = req.user?.email || req.body?.email || null;

        // Prepare audit log data
        const auditData = {
          userId,
          userEmail,
          action,
          resource: options.resource || null,
          resourceId: options.getResourceId ? options.getResourceId(req) : req.params?.id || null,
          details: sanitizeDetails({
            requestBody: req.body,
            queryParams: req.query,
            params: req.params,
            responseData: success ? responseData : null,
            duration: `${duration}ms`,
            ...options.additionalDetails
          }),
          ipAddress: getClientIP(req),
          userAgent: req.get('User-Agent') || null,
          endpoint: req.originalUrl,
          method: req.method,
          statusCode,
          success,
          errorMessage: !success && responseData?.message ? responseData.message : null,
          sessionId: req.sessionID || null
        };

        // Create audit log
        await AuditLog.createLog(auditData);

        // Log to winston
        const logLevel = success ? 'info' : 'warn';
        const logMessage = `${action} - ${req.method} ${req.originalUrl} - ${statusCode} - ${duration}ms - IP: ${auditData.ipAddress}`;
        
        logger[logLevel](logMessage, {
          userId,
          userEmail,
          action,
          statusCode,
          duration,
          ipAddress: auditData.ipAddress,
          success
        });

      } catch (error) {
        logger.error('Failed to create audit log:', error);
      }
    });

    next();
  };
};

// Specific audit loggers for common actions
const auditLoggers = {
  signup: auditLogger('USER_SIGNUP', { resource: 'user' }),
  login: auditLogger('USER_LOGIN', { resource: 'user' }),
  loginFailed: auditLogger('USER_LOGIN_FAILED', { resource: 'user' }),
  logout: auditLogger('USER_LOGOUT', { resource: 'user' }),
  emailVerification: auditLogger('EMAIL_VERIFICATION', { resource: 'user' }),
  emailVerificationFailed: auditLogger('EMAIL_VERIFICATION_FAILED', { resource: 'user' }),
  passwordResetRequest: auditLogger('PASSWORD_RESET_REQUEST', { resource: 'user' }),
  passwordResetSuccess: auditLogger('PASSWORD_RESET_SUCCESS', { resource: 'user' }),
  passwordResetFailed: auditLogger('PASSWORD_RESET_FAILED', { resource: 'user' }),
  adminApproval: auditLogger('ADMIN_APPROVAL', { 
    resource: 'user',
    getResourceId: (req) => req.params.id
  }),
  profileUpdate: auditLogger('PROFILE_UPDATE', { resource: 'user' }),
  unauthorizedAccess: auditLogger('UNAUTHORIZED_ACCESS_ATTEMPT', { resource: 'auth' }),
  suspiciousActivity: auditLogger('SUSPICIOUS_ACTIVITY', { resource: 'security' })
};

// Manual audit logging function
const createAuditLog = async (action, data = {}) => {
  try {
    const auditData = {
      action,
      success: data.success !== false,
      timestamp: new Date(),
      ...data
    };

    await AuditLog.createLog(auditData);
    
    const logLevel = auditData.success ? 'info' : 'warn';
    logger[logLevel](`Manual audit log: ${action}`, auditData);
    
  } catch (error) {
    logger.error('Failed to create manual audit log:', error);
  }
};

module.exports = {
  auditLogger,
  auditLoggers,
  createAuditLog,
  getClientIP,
  sanitizeDetails
};