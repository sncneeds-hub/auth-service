const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { createAuditLog } = require('./auditLogger');
const logger = require('../config/logger');

// Verify JWT token
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.header('Authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      logger.warn('Authentication failed - no token provided', {
        ip: req.ip,
        endpoint: req.originalUrl,
        userAgent: req.get('User-Agent')
      });
      
      // Create audit log for unauthorized access attempt
      await createAuditLog('UNAUTHORIZED_ACCESS_ATTEMPT', {
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl,
        method: req.method,
        success: false,
        errorMessage: 'No token provided'
      });
      
      return res.status(401).json({
        success: false,
        message: 'Access denied. No token provided or invalid format.'
      });
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Get user from database
      const user = await User.findById(decoded.id);
      if (!user) {
        logger.warn('Authentication failed - user not found', {
          userId: decoded.id,
          ip: req.ip,
          endpoint: req.originalUrl
        });
        
        // Create audit log for invalid user
        await createAuditLog('UNAUTHORIZED_ACCESS_ATTEMPT', {
          userId: decoded.id,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          endpoint: req.originalUrl,
          method: req.method,
          success: false,
          errorMessage: 'User no longer exists'
        });
        
        return res.status(401).json({
          success: false,
          message: 'Token is valid but user no longer exists'
        });
      }

      req.user = user;
      next();
    } catch (jwtError) {
      logger.warn('Authentication failed - invalid token', {
        error: jwtError.message,
        ip: req.ip,
        endpoint: req.originalUrl
      });
      
      // Create audit log for invalid token
      await createAuditLog('UNAUTHORIZED_ACCESS_ATTEMPT', {
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl,
        method: req.method,
        success: false,
        errorMessage: 'Invalid token'
      });
      
      return res.status(401).json({
        success: false,
        message: 'Invalid token'
      });
    }
  } catch (error) {
    logger.error('Authentication middleware error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during authentication'
    });
  }
};

// Role-based authorization
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      logger.warn('Authorization failed - user not authenticated', {
        ip: req.ip,
        endpoint: req.originalUrl,
        requiredRoles: roles
      });
      return res.status(401).json({
        success: false,
        message: 'Access denied. User not authenticated.'
      });
    }

    if (!roles.includes(req.user.role)) {
      logger.warn('Authorization failed - insufficient permissions', {
        userId: req.user._id,
        userEmail: req.user.email,
        userRole: req.user.role,
        requiredRoles: roles,
        ip: req.ip,
        endpoint: req.originalUrl
      });
      
      // Create audit log for insufficient permissions
      createAuditLog('UNAUTHORIZED_ACCESS_ATTEMPT', {
        userId: req.user._id,
        userEmail: req.user.email,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl,
        method: req.method,
        success: false,
        errorMessage: `Insufficient permissions. Required: ${roles.join(', ')}, Has: ${req.user.role}`
      });
      
      return res.status(403).json({
        success: false,
        message: `Access denied. Required roles: ${roles.join(', ')}`
      });
    }

    next();
  };
};

// Check if user is verified
const requireVerification = (req, res, next) => {
  if (!req.user.isVerified) {
    logger.warn('Access denied - user not verified', {
      userId: req.user._id,
      userEmail: req.user.email,
      ip: req.ip,
      endpoint: req.originalUrl
    });
    return res.status(403).json({
      success: false,
      message: 'Account not verified. Please verify your email first.'
    });
  }
  next();
};

// Check if user is approved by admin
const requireApproval = (req, res, next) => {
  if (!req.user.approvedByAdmin && req.user.role !== 'admin') {
    logger.warn('Access denied - user not approved', {
      userId: req.user._id,
      userEmail: req.user.email,
      role: req.user.role,
      ip: req.ip,
      endpoint: req.originalUrl
    });
    return res.status(403).json({
      success: false,
      message: 'Account pending admin approval.'
    });
  }
  next();
};

module.exports = {
  authenticate,
  authorize,
  requireVerification,
  requireApproval
};