const TokenUtils = require('../../../utils/tokenUtils');
const RefreshToken = require('../../../models/RefreshToken');
const User = require('../../../models/User');

// Mock dependencies
jest.mock('../../../models/RefreshToken');
jest.mock('../../../models/User');

describe('TokenUtils', () => {
  const mockUser = {
    _id: '507f1f77bcf86cd799439011',
    email: 'test@example.com',
    role: 'teacher'
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('generateTokenPair', () => {
    it('should generate access and refresh token pair', async () => {
      const mockRefreshToken = {
        token: 'mock-refresh-token',
        family: 'mock-family'
      };

      RefreshToken.createToken = jest.fn().mockResolvedValue(mockRefreshToken);

      const result = await TokenUtils.generateTokenPair(mockUser, {
        ipAddress: '192.168.1.1',
        userAgent: 'Test Browser'
      });

      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBe('mock-refresh-token');
      expect(result.refreshTokenFamily).toBe('mock-family');
      expect(result.expiresIn).toBeDefined();
      expect(result.refreshExpiresIn).toBe('30d');
      expect(RefreshToken.createToken).toHaveBeenCalledWith(
        mockUser._id,
        mockUser.email,
        expect.objectContaining({
          ipAddress: '192.168.1.1',
          userAgent: 'Test Browser'
        })
      );
    });
  });

  describe('refreshAccessToken', () => {
    it('should refresh access token successfully', async () => {
      const mockRefreshToken = {
        _id: 'token-id',
        token: 'old-refresh-token',
        userId: mockUser,
        family: 'token-family',
        lastUsedAt: null,
        save: jest.fn(),
        isRevoked: false,
        revokedAt: null,
        revokedBy: null,
        revokedReason: null
      };

      const mockNewRefreshToken = {
        token: 'new-refresh-token',
        family: 'token-family'
      };

      RefreshToken.findOne = jest.fn().mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockRefreshToken)
      });
      RefreshToken.createToken = jest.fn().mockResolvedValue(mockNewRefreshToken);

      const result = await TokenUtils.refreshAccessToken('old-refresh-token', {
        ipAddress: '192.168.1.1',
        userAgent: 'Test Browser'
      });

      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBe('new-refresh-token');
      expect(result.user).toBe(mockUser);
      expect(mockRefreshToken.save).toHaveBeenCalledTimes(2); // Once for lastUsedAt, once for revocation
      expect(mockRefreshToken.lastUsedAt).toBeDefined();
      expect(mockRefreshToken.isRevoked).toBe(true);
    });

    it('should throw error for invalid refresh token', async () => {
      RefreshToken.findOne = jest.fn().mockReturnValue({
        populate: jest.fn().mockResolvedValue(null)
      });

      await expect(
        TokenUtils.refreshAccessToken('invalid-token')
      ).rejects.toThrow('Invalid or expired refresh token');
    });

    it('should detect and handle token reuse', async () => {
      const mockRefreshToken = {
        _id: 'token-id',
        token: 'reused-token',
        userId: mockUser,
        family: 'token-family',
        lastUsedAt: new Date(), // Already used
        save: jest.fn()
      };

      RefreshToken.findOne = jest.fn().mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockRefreshToken)
      });
      RefreshToken.revokeFamily = jest.fn();

      await expect(
        TokenUtils.refreshAccessToken('reused-token')
      ).rejects.toThrow('Token reuse detected - all tokens revoked');

      expect(RefreshToken.revokeFamily).toHaveBeenCalledWith(
        'token-family',
        'system',
        'Token reuse detected'
      );
    });
  });

  describe('revokeRefreshToken', () => {
    it('should revoke refresh token successfully', async () => {
      const mockRefreshToken = {
        _id: 'token-id',
        token: 'refresh-token',
        isRevoked: false,
        save: jest.fn()
      };

      RefreshToken.findOne = jest.fn().mockResolvedValue(mockRefreshToken);

      const result = await TokenUtils.revokeRefreshToken('refresh-token', 'user', 'User logout');

      expect(result).toBe(true);
      expect(mockRefreshToken.isRevoked).toBe(true);
      expect(mockRefreshToken.revokedAt).toBeDefined();
      expect(mockRefreshToken.revokedBy).toBe('user');
      expect(mockRefreshToken.revokedReason).toBe('User logout');
      expect(mockRefreshToken.save).toHaveBeenCalled();
    });

    it('should throw error for non-existent token', async () => {
      RefreshToken.findOne = jest.fn().mockResolvedValue(null);

      await expect(
        TokenUtils.revokeRefreshToken('non-existent-token')
      ).rejects.toThrow('Refresh token not found or already revoked');
    });
  });

  describe('revokeAllUserTokens', () => {
    it('should revoke all user tokens', async () => {
      RefreshToken.revokeUserTokens = jest.fn().mockResolvedValue();

      const result = await TokenUtils.revokeAllUserTokens('user-id', 'admin', 'Security breach');

      expect(result).toBe(true);
      expect(RefreshToken.revokeUserTokens).toHaveBeenCalledWith('user-id', 'admin', 'Security breach');
    });
  });

  describe('getUserActiveTokens', () => {
    it('should return user active tokens', async () => {
      const mockTokens = [
        { token: 'token1', family: 'family1', createdAt: new Date() },
        { token: 'token2', family: 'family2', createdAt: new Date() }
      ];

      RefreshToken.find = jest.fn().mockReturnValue({
        select: jest.fn().mockResolvedValue(mockTokens)
      });

      const result = await TokenUtils.getUserActiveTokens('user-id');

      expect(result).toEqual(mockTokens);
      expect(RefreshToken.find).toHaveBeenCalledWith({
        userId: 'user-id',
        isRevoked: false,
        expiresAt: { $gt: expect.any(Date) }
      });
    });
  });

  describe('generateDeviceFingerprint', () => {
    it('should generate consistent fingerprint', () => {
      const fingerprint1 = TokenUtils.generateDeviceFingerprint('Chrome Browser', '192.168.1.1');
      const fingerprint2 = TokenUtils.generateDeviceFingerprint('Chrome Browser', '192.168.1.1');

      expect(fingerprint1).toBe(fingerprint2);
      expect(typeof fingerprint1).toBe('string');
      expect(fingerprint1.length).toBe(64); // SHA256 hex length
    });

    it('should generate different fingerprints for different inputs', () => {
      const fingerprint1 = TokenUtils.generateDeviceFingerprint('Chrome Browser', '192.168.1.1');
      const fingerprint2 = TokenUtils.generateDeviceFingerprint('Firefox Browser', '192.168.1.1');

      expect(fingerprint1).not.toBe(fingerprint2);
    });

    it('should handle additional data', () => {
      const fingerprint1 = TokenUtils.generateDeviceFingerprint('Chrome', '192.168.1.1');
      const fingerprint2 = TokenUtils.generateDeviceFingerprint('Chrome', '192.168.1.1', { extra: 'data' });

      expect(fingerprint1).not.toBe(fingerprint2);
    });
  });

  describe('cleanupExpiredTokens', () => {
    it('should cleanup expired tokens', async () => {
      RefreshToken.cleanupExpired = jest.fn().mockResolvedValue(5);

      const result = await TokenUtils.cleanupExpiredTokens();

      expect(result).toBe(5);
      expect(RefreshToken.cleanupExpired).toHaveBeenCalled();
    });
  });

  describe('getTokenStatistics', () => {
    it('should return token statistics', async () => {
      const mockStats = [{
        totalTokens: 100,
        activeTokens: 80,
        revokedTokens: 15,
        expiredTokens: 5
      }];

      RefreshToken.aggregate = jest.fn().mockResolvedValue(mockStats);

      const result = await TokenUtils.getTokenStatistics();

      expect(result).toEqual(mockStats[0]);
      expect(RefreshToken.aggregate).toHaveBeenCalled();
    });

    it('should return default stats when no data', async () => {
      RefreshToken.aggregate = jest.fn().mockResolvedValue([]);

      const result = await TokenUtils.getTokenStatistics();

      expect(result).toEqual({
        totalTokens: 0,
        activeTokens: 0,
        revokedTokens: 0,
        expiredTokens: 0
      });
    });
  });
});