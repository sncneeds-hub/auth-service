const mongoose = require('mongoose');

const userSecuritySchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true,
    index: true
  },
  userEmail: {
    type: String,
    required: true
  },
  isLocked: {
    type: Boolean,
    default: false,
    index: true
  },
  lockReason: {
    type: String,
    enum: ['failed_attempts', 'suspicious_activity', 'admin_action', 'security_breach'],
    default: null
  },
  lockedAt: {
    type: Date,
    default: null
  },
  lockedUntil: {
    type: Date,
    default: null,
    index: true
  },
  failedLoginAttempts: {
    type: Number,
    default: 0
  },
  lastFailedLogin: {
    type: Date,
    default: null
  },
  lastSuccessfulLogin: {
    type: Date,
    default: null
  },
  lastLoginIP: {
    type: String,
    default: null
  },
  suspiciousActivityCount: {
    type: Number,
    default: 0
  },
  lastSuspiciousActivity: {
    type: Date,
    default: null
  },
  knownIPs: [{
    ip: String,
    firstSeen: { type: Date, default: Date.now },
    lastSeen: { type: Date, default: Date.now },
    loginCount: { type: Number, default: 1 }
  }],
  knownDevices: [{
    fingerprint: String,
    userAgent: String,
    firstSeen: { type: Date, default: Date.now },
    lastSeen: { type: Date, default: Date.now },
    loginCount: { type: Number, default: 1 },
    trusted: { type: Boolean, default: false }
  }],
  securityEvents: [{
    type: {
      type: String,
      enum: ['login_success', 'login_failed', 'password_changed', 'suspicious_login', 'account_locked', 'account_unlocked']
    },
    timestamp: { type: Date, default: Date.now },
    ipAddress: String,
    userAgent: String,
    details: mongoose.Schema.Types.Mixed
  }],
  passwordChangedAt: {
    type: Date,
    default: null
  },
  mfaEnabled: {
    type: Boolean,
    default: false
  },
  mfaSecret: {
    type: String,
    default: null
  },
  backupCodes: [{
    code: String,
    used: { type: Boolean, default: false },
    usedAt: { type: Date, default: null }
  }]
}, {
  timestamps: true
});

// Index for efficient querying
userSecuritySchema.index({ 'knownIPs.ip': 1 });
userSecuritySchema.index({ 'securityEvents.timestamp': -1 });

// Method to record login attempt
userSecuritySchema.methods.recordLoginAttempt = async function(success, ipAddress, userAgent) {
  const now = new Date();
  
  if (success) {
    this.failedLoginAttempts = 0;
    this.lastSuccessfulLogin = now;
    this.lastLoginIP = ipAddress;
    
    // Update known IPs
    const knownIP = this.knownIPs.find(ip => ip.ip === ipAddress);
    if (knownIP) {
      knownIP.lastSeen = now;
      knownIP.loginCount += 1;
    } else {
      this.knownIPs.push({
        ip: ipAddress,
        firstSeen: now,
        lastSeen: now,
        loginCount: 1
      });
    }
    
    // Update known devices
    const deviceFingerprint = this.generateDeviceFingerprint(userAgent, ipAddress);
    const knownDevice = this.knownDevices.find(device => device.fingerprint === deviceFingerprint);
    if (knownDevice) {
      knownDevice.lastSeen = now;
      knownDevice.loginCount += 1;
    } else {
      this.knownDevices.push({
        fingerprint: deviceFingerprint,
        userAgent,
        firstSeen: now,
        lastSeen: now,
        loginCount: 1
      });
    }
    
    this.securityEvents.push({
      type: 'login_success',
      timestamp: now,
      ipAddress,
      userAgent
    });
  } else {
    this.failedLoginAttempts += 1;
    this.lastFailedLogin = now;
    
    this.securityEvents.push({
      type: 'login_failed',
      timestamp: now,
      ipAddress,
      userAgent
    });
    
    // Check if account should be locked
    if (this.failedLoginAttempts >= 5) {
      this.lockAccount('failed_attempts', 30); // Lock for 30 minutes
    }
  }
  
  await this.save();
};

// Method to lock account
userSecuritySchema.methods.lockAccount = function(reason, durationMinutes = 30) {
  const now = new Date();
  this.isLocked = true;
  this.lockReason = reason;
  this.lockedAt = now;
  this.lockedUntil = new Date(now.getTime() + (durationMinutes * 60 * 1000));
  
  this.securityEvents.push({
    type: 'account_locked',
    timestamp: now,
    details: { reason, durationMinutes }
  });
};

// Method to unlock account
userSecuritySchema.methods.unlockAccount = function() {
  const now = new Date();
  this.isLocked = false;
  this.lockReason = null;
  this.lockedAt = null;
  this.lockedUntil = null;
  this.failedLoginAttempts = 0;
  
  this.securityEvents.push({
    type: 'account_unlocked',
    timestamp: now
  });
};

// Method to check if account is locked
userSecuritySchema.methods.isAccountLocked = function() {
  if (!this.isLocked) return false;
  
  // Check if lock has expired
  if (this.lockedUntil && new Date() > this.lockedUntil) {
    this.unlockAccount();
    return false;
  }
  
  return true;
};

// Method to detect suspicious activity
userSecuritySchema.methods.detectSuspiciousActivity = function(ipAddress, userAgent) {
  const recentLogins = this.securityEvents
    .filter(event => event.type === 'login_success' && 
            event.timestamp > new Date(Date.now() - 24 * 60 * 60 * 1000))
    .length;
  
  const isNewIP = !this.knownIPs.some(ip => ip.ip === ipAddress);
  const isNewDevice = !this.knownDevices.some(device => 
    device.fingerprint === this.generateDeviceFingerprint(userAgent, ipAddress));
  
  // Suspicious if: new IP + new device + multiple recent logins
  return isNewIP && isNewDevice && recentLogins > 3;
};

// Method to generate device fingerprint
userSecuritySchema.methods.generateDeviceFingerprint = function(userAgent, ipAddress) {
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(`${userAgent}:${ipAddress}`).digest('hex');
};

// Static method to cleanup old security events
userSecuritySchema.statics.cleanupOldEvents = async function(daysToKeep = 90) {
  const cutoffDate = new Date(Date.now() - (daysToKeep * 24 * 60 * 60 * 1000));
  
  await this.updateMany(
    {},
    {
      $pull: {
        securityEvents: { timestamp: { $lt: cutoffDate } }
      }
    }
  );
};

module.exports = mongoose.model('UserSecurity', userSecuritySchema);