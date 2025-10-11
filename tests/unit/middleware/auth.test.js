const { authenticate, authorize, requireVerification, requireApproval } = require('../../../middleware/auth');
const User = require('../../../models/User');
const { generateToken } = require('../../../utils/jwt');

// Mock dependencies
jest.mock('../../../models/User');
jest.mock('../../../middleware/auditLogger', () => ({
  createAuditLog: jest.fn()
}));

describe('Auth Middleware', () => {
  let req, res, next;

  beforeEach(() => {
    req = {
      header: jest.fn(),
      ip: '192.168.1.1',
      originalUrl: '/test',
      method: 'GET',
      get: jest.fn().mockReturnValue('Test Browser')
    };
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    next = jest.fn();
    jest.clearAllMocks();
  });

  describe('authenticate', () => {
    it('should authenticate valid token', async () => {
      const testUser = {
        _id: '507f1f77bcf86cd799439011',
        email: 'test@example.com',
        role: 'teacher'
      };

      const token = generateToken({
        id: testUser._id,
        email: testUser.email,
        role: testUser.role
      });

      req.header.mockReturnValue(`Bearer ${token}`);
      User.findById.mockResolvedValue(testUser);

      await authenticate(req, res, next);

      expect(req.user).toEqual(testUser);
      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    it('should reject missing token', async () => {
      req.header.mockReturnValue(null);

      await authenticate(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        message: 'Access denied. No token provided or invalid format.'
      });
      expect(next).not.toHaveBeenCalled();
    });

    it('should reject invalid token format', async () => {
      req.header.mockReturnValue('InvalidFormat token');

      await authenticate(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        message: 'Access denied. No token provided or invalid format.'
      });
      expect(next).not.toHaveBeenCalled();
    });

    it('should reject invalid token', async () => {
      req.header.mockReturnValue('Bearer invalid-token');

      await authenticate(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        message: 'Invalid token'
      });
      expect(next).not.toHaveBeenCalled();
    });

    it('should reject token for non-existent user', async () => {
      const token = generateToken({
        id: '507f1f77bcf86cd799439011',
        email: 'test@example.com',
        role: 'teacher'
      });

      req.header.mockReturnValue(`Bearer ${token}`);
      User.findById.mockResolvedValue(null);

      await authenticate(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        message: 'Token is valid but user no longer exists'
      });
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe('authorize', () => {
    beforeEach(() => {
      req.user = {
        _id: '507f1f77bcf86cd799439011',
        email: 'test@example.com',
        role: 'teacher'
      };
    });

    it('should authorize user with correct role', () => {
      const middleware = authorize('teacher', 'admin');
      
      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    it('should reject user with incorrect role', () => {
      const middleware = authorize('admin');
      
      middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        message: 'Access denied. Required roles: admin'
      });
      expect(next).not.toHaveBeenCalled();
    });

    it('should reject unauthenticated user', () => {
      req.user = null;
      const middleware = authorize('teacher');
      
      middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        message: 'Access denied. User not authenticated.'
      });
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe('requireVerification', () => {
    it('should allow verified user', () => {
      req.user = {
        _id: '507f1f77bcf86cd799439011',
        email: 'test@example.com',
        isVerified: true
      };

      requireVerification(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    it('should reject unverified user', () => {
      req.user = {
        _id: '507f1f77bcf86cd799439011',
        email: 'test@example.com',
        isVerified: false
      };

      requireVerification(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        message: 'Account not verified. Please verify your email first.'
      });
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe('requireApproval', () => {
    it('should allow approved user', () => {
      req.user = {
        _id: '507f1f77bcf86cd799439011',
        email: 'test@example.com',
        role: 'teacher',
        approvedByAdmin: true
      };

      requireApproval(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    it('should allow admin user without approval', () => {
      req.user = {
        _id: '507f1f77bcf86cd799439011',
        email: 'admin@example.com',
        role: 'admin',
        approvedByAdmin: false
      };

      requireApproval(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    it('should reject unapproved non-admin user', () => {
      req.user = {
        _id: '507f1f77bcf86cd799439011',
        email: 'test@example.com',
        role: 'teacher',
        approvedByAdmin: false
      };

      requireApproval(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        message: 'Account pending admin approval.'
      });
      expect(next).not.toHaveBeenCalled();
    });
  });
});