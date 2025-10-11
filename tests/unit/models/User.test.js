const User = require('../../../models/User');
const bcrypt = require('bcryptjs');

describe('User Model', () => {
  describe('User Creation', () => {
    it('should create a user with valid data', async () => {
      const userData = {
        email: 'test@example.com',
        passwordHash: 'password123',
        role: 'teacher'
      };

      const user = new User(userData);
      const savedUser = await user.save();

      expect(savedUser._id).toBeDefined();
      expect(savedUser.email).toBe(userData.email);
      expect(savedUser.role).toBe(userData.role);
      expect(savedUser.isVerified).toBe(false);
      expect(savedUser.approvedByAdmin).toBe(false);
      expect(savedUser.createdAt).toBeDefined();
    });

    it('should hash password before saving', async () => {
      const plainPassword = 'password123';
      const user = new User({
        email: 'test@example.com',
        passwordHash: plainPassword,
        role: 'teacher'
      });

      await user.save();
      
      expect(user.passwordHash).not.toBe(plainPassword);
      expect(user.passwordHash.length).toBeGreaterThan(50);
    });

    it('should auto-approve admin accounts', async () => {
      const user = new User({
        email: 'admin@example.com',
        passwordHash: 'password123',
        role: 'admin'
      });

      await user.save();
      expect(user.approvedByAdmin).toBe(true);
    });
  });

  describe('Validation', () => {
    it('should require email', async () => {
      const user = new User({
        passwordHash: 'password123',
        role: 'teacher'
      });

      await expect(user.save()).rejects.toThrow('Email is required');
    });

    it('should require valid email format', async () => {
      const user = new User({
        email: 'invalid-email',
        passwordHash: 'password123',
        role: 'teacher'
      });

      await expect(user.save()).rejects.toThrow('Please enter a valid email');
    });

    it('should require password', async () => {
      const user = new User({
        email: 'test@example.com',
        role: 'teacher'
      });

      await expect(user.save()).rejects.toThrow('Password is required');
    });

    it('should require valid role', async () => {
      const user = new User({
        email: 'test@example.com',
        passwordHash: 'password123',
        role: 'invalid-role'
      });

      await expect(user.save()).rejects.toThrow();
    });

    it('should enforce unique email', async () => {
      const userData = {
        email: 'test@example.com',
        passwordHash: 'password123',
        role: 'teacher'
      };

      await new User(userData).save();
      
      const duplicateUser = new User(userData);
      await expect(duplicateUser.save()).rejects.toThrow();
    });
  });

  describe('Methods', () => {
    let user;

    beforeEach(async () => {
      user = await global.testHelpers.createTestUser();
    });

    it('should compare passwords correctly', async () => {
      const isMatch = await user.comparePassword('password123');
      expect(isMatch).toBe(true);

      const isNotMatch = await user.comparePassword('wrongpassword');
      expect(isNotMatch).toBe(false);
    });

    it('should generate verification token', () => {
      const token = user.generateVerificationToken();
      
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.length).toBe(64);
      expect(user.verificationToken).toBe(token);
    });

    it('should exclude sensitive fields from JSON', () => {
      const userJSON = user.toJSON();
      
      expect(userJSON.passwordHash).toBeUndefined();
      expect(userJSON.verificationToken).toBeUndefined();
      expect(userJSON.resetPasswordToken).toBeUndefined();
      expect(userJSON.email).toBeDefined();
      expect(userJSON.role).toBeDefined();
    });
  });
});