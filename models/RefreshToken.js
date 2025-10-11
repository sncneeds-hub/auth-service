const mongoose = require('mongoose');

const refreshTokenSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  userEmail: {
    type: String,
    required: true
  },
  family: {
    type: String,
    required: true,
    index: true
  },
  isRevoked: {
    type: Boolean,
    default: false,
    index: true
  },
  revokedAt: {
    type: Date,
    default: null
  },
  revokedBy: {
    type: String,
    enum: ['user', 'admin', 'system', 'rotation', 'suspicious'],
    default: null
  },
  revokedReason: {
    type: String,
    default: null
  },
  expiresAt: {
    type: Date,
    required: true,
    index: { expireAfterSeconds: 0 }
  },
  lastUsedAt: {
    type: Date,
    default: null
  },
  ipAddress: {
    type: String,
    default: null
  },
  userAgent: {
    type: String,
    default: null
  },
  deviceFingerprint: {
    type: String,
    default: null
  }
}, {
  timestamps: true
});

// Index for efficient querying
refreshTokenSchema.index({ userId: 1, isRevoked: 1 });
refreshTokenSchema.index({ family: 1, isRevoked: 1 });
refreshTokenSchema.index({ expiresAt: 1 });

// Static method to create refresh token
refreshTokenSchema.statics.createToken = async function(userId, userEmail, options = {}) {
  const crypto = require('crypto');
  
  const token = crypto.randomBytes(64).toString('hex');
  const family = options.family || crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + (30 * 24 * 60 * 60 * 1000)); // 30 days

  const refreshToken = new this({
    token,
    userId,
    userEmail,
    family,
    expiresAt,
    ipAddress: options.ipAddress,
    userAgent: options.userAgent,
    deviceFingerprint: options.deviceFingerprint
  });

  await refreshToken.save();
  return refreshToken;
};

// Static method to revoke token family
refreshTokenSchema.statics.revokeFamily = async function(family, revokedBy = 'system', reason = null) {
  await this.updateMany(
    { family, isRevoked: false },
    {
      isRevoked: true,
      revokedAt: new Date(),
      revokedBy,
      revokedReason: reason
    }
  );
};

// Static method to revoke user tokens
refreshTokenSchema.statics.revokeUserTokens = async function(userId, revokedBy = 'user', reason = null) {
  await this.updateMany(
    { userId, isRevoked: false },
    {
      isRevoked: true,
      revokedAt: new Date(),
      revokedBy,
      revokedReason: reason
    }
  );
};

// Static method to cleanup expired tokens
refreshTokenSchema.statics.cleanupExpired = async function() {
  const result = await this.deleteMany({
    expiresAt: { $lt: new Date() }
  });
  return result.deletedCount;
};

module.exports = mongoose.model('RefreshToken', refreshTokenSchema);