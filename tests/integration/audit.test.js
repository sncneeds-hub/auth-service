const request = require('supertest');
const app = require('../../index');
const AuditLog = require('../../models/AuditLog');
const { generateToken } = require('../../utils/jwt');

describe('Audit Routes Integration', () => {
  let adminUser;
  let teacherUser;
  let adminToken;
  let teacherToken;

  beforeEach(async () => {
    adminUser = await global.testHelpers.createTestAdmin();
    teacherUser = await global.testHelpers.createTestUser();
    
    adminToken = generateToken({
      id: adminUser._id,
      email: adminUser.email,
      role: adminUser.role
    });
    
    teacherToken = generateToken({
      id: teacherUser._id,
      email: teacherUser.email,
      role: teacherUser.role
    });

    // Create test audit logs
    await AuditLog.createLog({
      userId: teacherUser._id,
      userEmail: teacherUser.email,
      action: 'USER_LOGIN',
      success: true,
      ipAddress: '192.168.1.1',
      userAgent: 'Test Browser'
    });

    await AuditLog.createLog({
      userId: teacherUser._id,
      userEmail: teacherUser.email,
      action: 'USER_LOGIN_FAILED',
      success: false,
      ipAddress: '192.168.1.1',
      userAgent: 'Test Browser',
      errorMessage: 'Invalid credentials'
    });
  });

  describe('GET /api/audit/logs', () => {
    it('should return audit logs for admin', async () => {
      const response = await request(app)
        .get('/api/audit/logs')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.logs).toBeDefined();
      expect(response.body.data.pagination).toBeDefined();
      expect(Array.isArray(response.body.data.logs)).toBe(true);
    });

    it('should filter logs by action', async () => {
      const response = await request(app)
        .get('/api/audit/logs?action=USER_LOGIN')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      response.body.data.logs.forEach(log => {
        expect(log.action).toBe('USER_LOGIN');
      });
    });

    it('should filter logs by success status', async () => {
      const response = await request(app)
        .get('/api/audit/logs?success=false')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      response.body.data.logs.forEach(log => {
        expect(log.success).toBe(false);
      });
    });

    it('should reject non-admin user', async () => {
      const response = await request(app)
        .get('/api/audit/logs')
        .set('Authorization', `Bearer ${teacherToken}`)
        .expect(403);

      expect(response.body.success).toBe(false);
    });
  });

  describe('GET /api/audit/user/:userId', () => {
    it('should return user activity for admin', async () => {
      const response = await request(app)
        .get(`/api/audit/user/${teacherUser._id}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.logs).toBeDefined();
      expect(response.body.data.pagination).toBeDefined();
    });

    it('should allow user to view own activity', async () => {
      const response = await request(app)
        .get(`/api/audit/user/${teacherUser._id}`)
        .set('Authorization', `Bearer ${teacherToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.logs).toBeDefined();
    });

    it('should reject user viewing other user activity', async () => {
      const otherUser = await global.testHelpers.createTestUser({
        email: 'other@example.com'
      });

      const response = await request(app)
        .get(`/api/audit/user/${otherUser._id}`)
        .set('Authorization', `Bearer ${teacherToken}`)
        .expect(403);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('You can only view your own activity logs');
    });
  });

  describe('GET /api/audit/security', () => {
    beforeEach(async () => {
      // Create security events
      await AuditLog.createLog({
        action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        success: false,
        ipAddress: '192.168.1.100',
        userAgent: 'Suspicious Browser',
        errorMessage: 'Invalid token'
      });

      await AuditLog.createLog({
        action: 'SUSPICIOUS_ACTIVITY',
        success: false,
        ipAddress: '192.168.1.100',
        userAgent: 'Suspicious Browser'
      });
    });

    it('should return security events for admin', async () => {
      const response = await request(app)
        .get('/api/audit/security')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.logs).toBeDefined();
      expect(response.body.data.pagination).toBeDefined();
      
      // Should only contain security-related actions
      const securityActions = [
        'USER_LOGIN_FAILED',
        'EMAIL_VERIFICATION_FAILED',
        'PASSWORD_RESET_FAILED',
        'UNAUTHORIZED_ACCESS_ATTEMPT',
        'SUSPICIOUS_ACTIVITY',
        'ACCOUNT_LOCKED'
      ];
      
      response.body.data.logs.forEach(log => {
        expect(securityActions).toContain(log.action);
      });
    });

    it('should reject non-admin user', async () => {
      const response = await request(app)
        .get('/api/audit/security')
        .set('Authorization', `Bearer ${teacherToken}`)
        .expect(403);

      expect(response.body.success).toBe(false);
    });
  });

  describe('GET /api/audit/stats', () => {
    it('should return audit statistics for admin', async () => {
      const response = await request(app)
        .get('/api/audit/stats')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.summary).toBeDefined();
      expect(response.body.data.topActions).toBeDefined();
      expect(response.body.data.topIPs).toBeDefined();
      expect(response.body.data.dailyActivity).toBeDefined();
      expect(response.body.data.period).toBeDefined();

      // Check summary structure
      expect(response.body.data.summary.totalLogs).toBeDefined();
      expect(response.body.data.summary.successCount).toBeDefined();
      expect(response.body.data.summary.failureCount).toBeDefined();
      expect(response.body.data.summary.successRate).toBeDefined();
    });

    it('should accept custom time period', async () => {
      const response = await request(app)
        .get('/api/audit/stats?days=30')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.period.days).toBe(30);
    });

    it('should reject non-admin user', async () => {
      const response = await request(app)
        .get('/api/audit/stats')
        .set('Authorization', `Bearer ${teacherToken}`)
        .expect(403);

      expect(response.body.success).toBe(false);
    });
  });
});