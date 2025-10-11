const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  userEmail: {
    type: String,
    default: null
  },
  action: {
    type: String,
    required: [true, 'Action is required'],
    enum: [
      'USER_SIGNUP',
      'USER_LOGIN',
      'USER_LOGIN_FAILED',
      'USER_LOGOUT',
      'EMAIL_VERIFICATION',
      'EMAIL_VERIFICATION_FAILED',
      'PASSWORD_RESET_REQUEST',
      'PASSWORD_RESET_SUCCESS',
      'PASSWORD_RESET_FAILED',
      'ADMIN_APPROVAL',
      'ADMIN_REJECTION',
      'PROFILE_UPDATE',
      'ROLE_CHANGE',
      'ACCOUNT_LOCKED',
      'ACCOUNT_UNLOCKED',
      'TOKEN_REFRESH',
      'UNAUTHORIZED_ACCESS_ATTEMPT',
      'SUSPICIOUS_ACTIVITY'
    ]
  },
  resource: {
    type: String,
    default: null // e.g., 'user', 'profile', 'settings'
  },
  resourceId: {
    type: String,
    default: null // ID of the affected resource
  },
  details: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  ipAddress: {
    type: String,
    default: null
  },
  userAgent: {
    type: String,
    default: null
  },
  endpoint: {
    type: String,
    default: null
  },
  method: {
    type: String,
    enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    default: null
  },
  statusCode: {
    type: Number,
    default: null
  },
  success: {
    type: Boolean,
    required: true
  },
  errorMessage: {
    type: String,
    default: null
  },
  sessionId: {
    type: String,
    default: null
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true,
  collection: 'audit_logs'
});

// Index for efficient querying
auditLogSchema.index({ userId: 1, timestamp: -1 });
auditLogSchema.index({ action: 1, timestamp: -1 });
auditLogSchema.index({ ipAddress: 1, timestamp: -1 });
auditLogSchema.index({ timestamp: -1 });
auditLogSchema.index({ success: 1, timestamp: -1 });

// Static method to create audit log
auditLogSchema.statics.createLog = async function(logData) {
  try {
    const auditLog = new this(logData);
    await auditLog.save();
    return auditLog;
  } catch (error) {
    console.error('Failed to create audit log:', error);
    // Don't throw error to prevent breaking the main flow
    return null;
  }
};

// Static method to get user activity
auditLogSchema.statics.getUserActivity = async function(userId, options = {}) {
  const {
    page = 1,
    limit = 50,
    action,
    startDate,
    endDate,
    success
  } = options;

  const filter = { userId };
  
  if (action) filter.action = action;
  if (success !== undefined) filter.success = success;
  if (startDate || endDate) {
    filter.timestamp = {};
    if (startDate) filter.timestamp.$gte = new Date(startDate);
    if (endDate) filter.timestamp.$lte = new Date(endDate);
  }

  const logs = await this.find(filter)
    .sort({ timestamp: -1 })
    .limit(limit * 1)
    .skip((page - 1) * limit)
    .lean();

  const total = await this.countDocuments(filter);

  return {
    logs,
    pagination: {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    }
  };
};

// Static method to get security events
auditLogSchema.statics.getSecurityEvents = async function(options = {}) {
  const {
    page = 1,
    limit = 100,
    hours = 24
  } = options;

  const startTime = new Date(Date.now() - (hours * 60 * 60 * 1000));
  
  const securityActions = [
    'USER_LOGIN_FAILED',
    'EMAIL_VERIFICATION_FAILED',
    'PASSWORD_RESET_FAILED',
    'UNAUTHORIZED_ACCESS_ATTEMPT',
    'SUSPICIOUS_ACTIVITY',
    'ACCOUNT_LOCKED'
  ];

  const logs = await this.find({
    action: { $in: securityActions },
    timestamp: { $gte: startTime }
  })
    .sort({ timestamp: -1 })
    .limit(limit * 1)
    .skip((page - 1) * limit)
    .lean();

  const total = await this.countDocuments({
    action: { $in: securityActions },
    timestamp: { $gte: startTime }
  });

  return {
    logs,
    pagination: {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    }
  };
};

module.exports = mongoose.model('AuditLog', auditLogSchema);