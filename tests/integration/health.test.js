const request = require('supertest');
const app = require('../../index');
const { generateToken } = require('../../utils/jwt');

describe('Health Routes Integration', () => {
  describe('GET /api/health', () => {
    it('should return basic health status', async () => {
      const response = await request(app)
        .get('/api/health')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.status).toBeDefined();
      expect(response.body.timestamp).toBeDefined();
      expect(response.body.uptime).toBeDefined();
      expect(response.body.version).toBeDefined();
      expect(response.body.checks).toBeDefined();
    });

    it('should include database health check', async () => {
      const response = await request(app)
        .get('/api/health')
        .expect(200);

      expect(response.body.checks.database).toBeDefined();
      expect(response.body.checks.database.status).toBeDefined();
    });
  });

  describe('GET /api/health/detailed', () => {
    let adminUser;
    let adminToken;

    beforeEach(async () => {
      adminUser = await global.testHelpers.createTestAdmin();
      adminToken = generateToken({
        id: adminUser._id,
        email: adminUser.email,
        role: adminUser.role
      });
    });

    it('should return detailed health report for admin', async () => {
      const response = await request(app)
        .get('/api/health/detailed')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.status).toBeDefined();
      expect(response.body.checks).toBeDefined();
      expect(response.body.metrics).toBeDefined();
      expect(response.body.metrics.requestCount).toBeDefined();
      expect(response.body.metrics.errorCount).toBeDefined();
    });

    it('should reject non-admin user', async () => {
      const teacherUser = await global.testHelpers.createTestUser();
      const teacherToken = generateToken({
        id: teacherUser._id,
        email: teacherUser.email,
        role: 'teacher'
      });

      const response = await request(app)
        .get('/api/health/detailed')
        .set('Authorization', `Bearer ${teacherToken}`)
        .expect(403);

      expect(response.body.success).toBe(false);
    });
  });

  describe('GET /api/health/ready', () => {
    it('should return readiness status', async () => {
      const response = await request(app)
        .get('/api/health/ready')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.status).toBe('ready');
      expect(response.body.timestamp).toBeDefined();
    });
  });

  describe('GET /api/health/live', () => {
    it('should return liveness status', async () => {
      const response = await request(app)
        .get('/api/health/live')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.status).toBe('alive');
      expect(response.body.timestamp).toBeDefined();
      expect(response.body.uptime).toBeDefined();
    });
  });

  describe('GET /api/health/metrics', () => {
    let adminUser;
    let adminToken;

    beforeEach(async () => {
      adminUser = await global.testHelpers.createTestAdmin();
      adminToken = generateToken({
        id: adminUser._id,
        email: adminUser.email,
        role: adminUser.role
      });
    });

    it('should return system metrics for admin', async () => {
      const response = await request(app)
        .get('/api/health/metrics')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toBeDefined();
      expect(response.body.data.system).toBeDefined();
      expect(response.body.data.database).toBeDefined();
    });

    it('should reject non-admin user', async () => {
      const teacherUser = await global.testHelpers.createTestUser();
      const teacherToken = generateToken({
        id: teacherUser._id,
        email: teacherUser.email,
        role: 'teacher'
      });

      const response = await request(app)
        .get('/api/health/metrics')
        .set('Authorization', `Bearer ${teacherToken}`)
        .expect(403);

      expect(response.body.success).toBe(false);
    });
  });
});