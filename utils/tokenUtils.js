const crypto = require('crypto');
const RefreshToken = require('../models/RefreshToken');
const { generateToken } = require('./jwt');
const logger = require('../config/logger');

class TokenUtils {
  // Generate access and refresh token pair
  static async generateTokenPair(user, options = {}) {
    try {
      // Generate access token (short-lived)
      const accessToken = generateToken({
        id: user._id,
        email: user.email,
        role: user.role
      });

      // Generate refresh token (long-lived)
      const refreshToken = await RefreshToken.createToken(
        user._id,
        user.email,
        {
          family: options.family,
          ipAddress: options.ipAddress,
          userAgent: options.userAgent,
          deviceFingerprint: options.deviceFingerprint
        }
      );

      return {
        accessToken,
        refreshToken: refreshToken.token,
        refreshTokenFamily: refreshToken.family,
        expiresIn: process.env.JWT_EXPIRE || '15m',
        refreshExpiresIn: '30d'
      };
    } catch (error) {
      logger.error('Failed to generate token pair:', error);
      throw new Error('Token generation failed');
    }
  }

  // Refresh access token using refresh token
  static async refreshAccessToken(refreshTokenString, options = {}) {
    try {
      // Find the refresh token
      const refreshToken = await RefreshToken.findOne({
        token: refreshTokenString,
        isRevoked: false,
        expiresAt: { $gt: new Date() }
      }).populate('userId');

      if (!refreshToken) {
        throw new Error('Invalid or expired refresh token');
      }

      // Check for token reuse (security measure)
      if (refreshToken.lastUsedAt) {
        // Token has been used before - potential security issue
        logger.warn('Refresh token reuse detected', {
          tokenId: refreshToken._id,
          userId: refreshToken.userId,
          family: refreshToken.family,
          ipAddress: options.ipAddress
        });

        // Revoke the entire token family
        await RefreshToken.revokeFamily(
          refreshToken.family,
          'system',
          'Token reuse detected'
        );

        throw new Error('Token reuse detected - all tokens revoked');
      }

      // Update last used timestamp
      refreshToken.lastUsedAt = new Date();
      await refreshToken.save();

      // Generate new token pair (token rotation)
      const newTokenPair = await this.generateTokenPair(
        refreshToken.userId,
        {
          family: refreshToken.family, // Keep same family
          ipAddress: options.ipAddress,
          userAgent: options.userAgent,
          deviceFingerprint: options.deviceFingerprint
        }
      );

      // Revoke the old refresh token
      refreshToken.isRevoked = true;
      refreshToken.revokedAt = new Date();
      refreshToken.revokedBy = 'rotation';
      refreshToken.revokedReason = 'Token rotated';
      await refreshToken.save();

      logger.info('Access token refreshed successfully', {
        userId: refreshToken.userId._id,
        userEmail: refreshToken.userId.email,
        oldTokenId: refreshToken._id,
        family: refreshToken.family
      });

      return {
        ...newTokenPair,
        user: refreshToken.userId
      };
    } catch (error) {
      logger.error('Token refresh failed:', error);
      throw error;
    }
  }

  // Revoke refresh token
  static async revokeRefreshToken(refreshTokenString, revokedBy = 'user', reason = null) {
    try {
      const refreshToken = await RefreshToken.findOne({
        token: refreshTokenString,
        isRevoked: false
      });

      if (!refreshToken) {
        throw new Error('Refresh token not found or already revoked');
      }

      refreshToken.isRevoked = true;
      refreshToken.revokedAt = new Date();
      refreshToken.revokedBy = revokedBy;
      refreshToken.revokedReason = reason;
      await refreshToken.save();

      logger.info('Refresh token revoked', {
        tokenId: refreshToken._id,
        userId: refreshToken.userId,
        revokedBy,
        reason
      });

      return true;
    } catch (error) {
      logger.error('Token revocation failed:', error);
      throw error;
    }
  }

  // Revoke all user tokens
  static async revokeAllUserTokens(userId, revokedBy = 'user', reason = null) {
    try {
      await RefreshToken.revokeUserTokens(userId, revokedBy, reason);
      
      logger.info('All user tokens revoked', {
        userId,
        revokedBy,
        reason
      });

      return true;
    } catch (error) {
      logger.error('Failed to revoke all user tokens:', error);
      throw error;
    }
  }

  // Get user's active refresh tokens
  static async getUserActiveTokens(userId) {
    try {
      const tokens = await RefreshToken.find({
        userId,
        isRevoked: false,
        expiresAt: { $gt: new Date() }
      }).select('token family createdAt lastUsedAt ipAddress userAgent deviceFingerprint');

      return tokens;
    } catch (error) {
      logger.error('Failed to get user active tokens:', error);
      throw error;
    }
  }

  // Generate device fingerprint
  static generateDeviceFingerprint(userAgent, ipAddress, additionalData = {}) {
    const data = {
      userAgent: userAgent || '',
      ipAddress: ipAddress || '',
      ...additionalData
    };

    return crypto
      .createHash('sha256')
      .update(JSON.stringify(data))
      .digest('hex');
  }

  // Cleanup expired tokens (should be run periodically)
  static async cleanupExpiredTokens() {
    try {
      const deletedCount = await RefreshToken.cleanupExpired();
      
      if (deletedCount > 0) {
        logger.info(`Cleaned up ${deletedCount} expired refresh tokens`);
      }

      return deletedCount;
    } catch (error) {
      logger.error('Token cleanup failed:', error);
      throw error;
    }
  }

  // Get token statistics
  static async getTokenStatistics() {
    try {
      const stats = await RefreshToken.aggregate([
        {
          $group: {
            _id: null,
            totalTokens: { $sum: 1 },
            activeTokens: {
              $sum: {
                $cond: [
                  {
                    $and: [
                      { $eq: ['$isRevoked', false] },
                      { $gt: ['$expiresAt', new Date()] }
                    ]
                  },
                  1,
                  0
                ]
              }
            },
            revokedTokens: {
              $sum: { $cond: [{ $eq: ['$isRevoked', true] }, 1, 0] }
            },
            expiredTokens: {
              $sum: {
                $cond: [
                  { $lte: ['$expiresAt', new Date()] },
                  1,
                  0
                ]
              }
            }
          }
        }
      ]);

      return stats[0] || {
        totalTokens: 0,
        activeTokens: 0,
        revokedTokens: 0,
        expiredTokens: 0
      };
    } catch (error) {
      logger.error('Failed to get token statistics:', error);
      throw error;
    }
  }
}

module.exports = TokenUtils;