const request = require('supertest');
const app = require('../../index');
const User = require('../../models/User');
const { generateToken } = require('../../utils/jwt');

describe('Auth Routes Integration', () => {
  describe('POST /api/auth/signup', () => {
    it('should register a new user successfully', async () => {
      const userData = {
        email: 'newuser@example.com',
        password: 'password123',
        role: 'teacher'
      };

      const response = await request(app)
        .post('/api/auth/signup')
        .send(userData)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('User registered successfully');
      expect(response.body.data.user.email).toBe(userData.email);
      expect(response.body.data.user.role).toBe(userData.role);
      expect(response.body.data.user.isVerified).toBe(false);
      expect(response.body.data.accessToken).toBeDefined();
      expect(response.body.data.refreshToken).toBeDefined();
      expect(response.body.data.verificationToken).toBeDefined();

      // Verify user was created in database
      const user = await User.findOne({ email: userData.email });
      expect(user).toBeTruthy();
      expect(user.role).toBe(userData.role);
    });

    it('should auto-approve admin accounts', async () => {
      const adminData = {
        email: 'admin@example.com',
        password: 'password123',
        role: 'admin'
      };

      const response = await request(app)
        .post('/api/auth/signup')
        .send(adminData)
        .expect(201);

      expect(response.body.data.user.approvedByAdmin).toBe(true);
    });

    it('should reject invalid email', async () => {
      const userData = {
        email: 'invalid-email',
        password: 'password123',
        role: 'teacher'
      };

      const response = await request(app)
        .post('/api/auth/signup')
        .send(userData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Validation failed');
    });

    it('should reject duplicate email', async () => {
      const userData = {
        email: 'duplicate@example.com',
        password: 'password123',
        role: 'teacher'
      };

      // Create first user
      await request(app)
        .post('/api/auth/signup')
        .send(userData)
        .expect(201);

      // Try to create duplicate
      const response = await request(app)
        .post('/api/auth/signup')
        .send(userData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('User already exists with this email');
    });
  });

  describe('POST /api/auth/login', () => {
    let testUser;

    beforeEach(async () => {
      testUser = await global.testHelpers.createTestUser({
        email: 'login@example.com',
        passwordHash: 'password123'
      });
    });

    it('should login with valid credentials', async () => {
      const loginData = {
        email: 'login@example.com',
        password: 'password123'
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(loginData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('Login successful');
      expect(response.body.data.user.email).toBe(loginData.email);
      expect(response.body.data.accessToken).toBeDefined();
      expect(response.body.data.refreshToken).toBeDefined();
    });

    it('should reject invalid email', async () => {
      const loginData = {
        email: 'nonexistent@example.com',
        password: 'password123'
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(loginData)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Invalid credentials');
    });

    it('should reject invalid password', async () => {
      const loginData = {
        email: 'login@example.com',
        password: 'wrongpassword'
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(loginData)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Invalid credentials');
    });
  });

  describe('POST /api/auth/verify', () => {
    let testUser;

    beforeEach(async () => {
      testUser = await global.testHelpers.createTestUser({
        email: 'verify@example.com',
        isVerified: false
      });
      testUser.generateVerificationToken();
      await testUser.save();
    });

    it('should verify email with valid token', async () => {
      const verifyData = {
        email: testUser.email,
        verificationToken: testUser.verificationToken
      };

      const response = await request(app)
        .post('/api/auth/verify')
        .send(verifyData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('Email verified successfully');
      expect(response.body.data.user.isVerified).toBe(true);

      // Verify in database
      const updatedUser = await User.findById(testUser._id);
      expect(updatedUser.isVerified).toBe(true);
      expect(updatedUser.verificationToken).toBeNull();
    });

    it('should reject invalid verification token', async () => {
      const verifyData = {
        email: testUser.email,
        verificationToken: 'invalid-token'
      };

      const response = await request(app)
        .post('/api/auth/verify')
        .send(verifyData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Invalid verification token or email');
    });
  });

  describe('GET /api/auth/me', () => {
    let testUser;
    let authToken;

    beforeEach(async () => {
      testUser = await global.testHelpers.createTestUser();
      authToken = generateToken({
        id: testUser._id,
        email: testUser.email,
        role: testUser.role
      });
    });

    it('should return user profile with valid token', async () => {
      const response = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.user.email).toBe(testUser.email);
      expect(response.body.data.user.role).toBe(testUser.role);
      expect(response.body.data.user.passwordHash).toBeUndefined();
    });

    it('should reject request without token', async () => {
      const response = await request(app)
        .get('/api/auth/me')
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Access denied. No token provided or invalid format.');
    });

    it('should reject request with invalid token', async () => {
      const response = await request(app)
        .get('/api/auth/me')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Invalid token');
    });
  });

  describe('PUT /api/auth/approve/:id', () => {
    let adminUser;
    let testUser;
    let adminToken;

    beforeEach(async () => {
      adminUser = await global.testHelpers.createTestAdmin();
      testUser = await global.testHelpers.createTestUser({
        email: 'pending@example.com',
        approvedByAdmin: false
      });
      
      adminToken = generateToken({
        id: adminUser._id,
        email: adminUser.email,
        role: adminUser.role
      });
    });

    it('should approve user as admin', async () => {
      const response = await request(app)
        .put(`/api/auth/approve/${testUser._id}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('User approved successfully');
      expect(response.body.data.user.approvedByAdmin).toBe(true);

      // Verify in database
      const updatedUser = await User.findById(testUser._id);
      expect(updatedUser.approvedByAdmin).toBe(true);
    });

    it('should reject non-admin user', async () => {
      const teacherToken = generateToken({
        id: testUser._id,
        email: testUser.email,
        role: 'teacher'
      });

      const response = await request(app)
        .put(`/api/auth/approve/${testUser._id}`)
        .set('Authorization', `Bearer ${teacherToken}`)
        .expect(403);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Access denied. Required roles: admin');
    });
  });

  describe('GET /api/auth/users', () => {
    let adminUser;
    let adminToken;

    beforeEach(async () => {
      adminUser = await global.testHelpers.createTestAdmin();
      adminToken = generateToken({
        id: adminUser._id,
        email: adminUser.email,
        role: adminUser.role
      });

      // Create test users
      await global.testHelpers.createTestUser({ email: 'teacher1@example.com', role: 'teacher' });
      await global.testHelpers.createTestUser({ email: 'school1@example.com', role: 'school' });
      await global.testHelpers.createTestUser({ email: 'vendor1@example.com', role: 'vendor' });
    });

    it('should return users list for admin', async () => {
      const response = await request(app)
        .get('/api/auth/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.users).toBeDefined();
      expect(response.body.data.pagination).toBeDefined();
      expect(response.body.data.users.length).toBeGreaterThan(0);
    });

    it('should filter users by role', async () => {
      const response = await request(app)
        .get('/api/auth/users?role=teacher')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      response.body.data.users.forEach(user => {
        expect(user.role).toBe('teacher');
      });
    });

    it('should reject non-admin user', async () => {
      const teacherUser = await global.testHelpers.createTestUser();
      const teacherToken = generateToken({
        id: teacherUser._id,
        email: teacherUser.email,
        role: 'teacher'
      });

      const response = await request(app)
        .get('/api/auth/users')
        .set('Authorization', `Bearer ${teacherToken}`)
        .expect(403);

      expect(response.body.success).toBe(false);
    });
  });
});