const UserSecurity = require('../../../models/UserSecurity');

describe('UserSecurity Model', () => {
  let userSecurity;

  beforeEach(async () => {
    userSecurity = new UserSecurity({
      userId: '507f1f77bcf86cd799439011',
      userEmail: 'test@example.com'
    });
    await userSecurity.save();
  });

  describe('recordLoginAttempt', () => {
    it('should record successful login attempt', async () => {
      await userSecurity.recordLoginAttempt(true, '192.168.1.1', 'Test Browser');

      expect(userSecurity.failedLoginAttempts).toBe(0);
      expect(userSecurity.lastSuccessfulLogin).toBeDefined();
      expect(userSecurity.lastLoginIP).toBe('192.168.1.1');
      expect(userSecurity.knownIPs).toHaveLength(1);
      expect(userSecurity.knownIPs[0].ip).toBe('192.168.1.1');
      expect(userSecurity.securityEvents).toHaveLength(1);
      expect(userSecurity.securityEvents[0].type).toBe('login_success');
    });

    it('should record failed login attempt', async () => {
      await userSecurity.recordLoginAttempt(false, '192.168.1.1', 'Test Browser');

      expect(userSecurity.failedLoginAttempts).toBe(1);
      expect(userSecurity.lastFailedLogin).toBeDefined();
      expect(userSecurity.securityEvents).toHaveLength(1);
      expect(userSecurity.securityEvents[0].type).toBe('login_failed');
    });

    it('should lock account after 5 failed attempts', async () => {
      // Record 5 failed attempts
      for (let i = 0; i < 5; i++) {
        await userSecurity.recordLoginAttempt(false, '192.168.1.1', 'Test Browser');
      }

      expect(userSecurity.isLocked).toBe(true);
      expect(userSecurity.lockReason).toBe('failed_attempts');
      expect(userSecurity.lockedUntil).toBeDefined();
    });

    it('should reset failed attempts on successful login', async () => {
      // Record failed attempts
      userSecurity.failedLoginAttempts = 3;
      
      await userSecurity.recordLoginAttempt(true, '192.168.1.1', 'Test Browser');

      expect(userSecurity.failedLoginAttempts).toBe(0);
    });

    it('should track known devices', async () => {
      await userSecurity.recordLoginAttempt(true, '192.168.1.1', 'Chrome Browser');
      await userSecurity.recordLoginAttempt(true, '192.168.1.1', 'Firefox Browser');

      expect(userSecurity.knownDevices).toHaveLength(2);
      expect(userSecurity.knownDevices[0].userAgent).toBe('Chrome Browser');
      expect(userSecurity.knownDevices[1].userAgent).toBe('Firefox Browser');
    });
  });

  describe('lockAccount', () => {
    it('should lock account with reason and duration', () => {
      userSecurity.lockAccount('suspicious_activity', 60);

      expect(userSecurity.isLocked).toBe(true);
      expect(userSecurity.lockReason).toBe('suspicious_activity');
      expect(userSecurity.lockedAt).toBeDefined();
      expect(userSecurity.lockedUntil).toBeDefined();
      expect(userSecurity.securityEvents).toHaveLength(1);
      expect(userSecurity.securityEvents[0].type).toBe('account_locked');
    });
  });

  describe('unlockAccount', () => {
    beforeEach(() => {
      userSecurity.lockAccount('failed_attempts', 30);
    });

    it('should unlock account and reset fields', () => {
      userSecurity.unlockAccount();

      expect(userSecurity.isLocked).toBe(false);
      expect(userSecurity.lockReason).toBeNull();
      expect(userSecurity.lockedAt).toBeNull();
      expect(userSecurity.lockedUntil).toBeNull();
      expect(userSecurity.failedLoginAttempts).toBe(0);
      expect(userSecurity.securityEvents).toHaveLength(2); // lock + unlock events
      expect(userSecurity.securityEvents[1].type).toBe('account_unlocked');
    });
  });

  describe('isAccountLocked', () => {
    it('should return false for unlocked account', () => {
      expect(userSecurity.isAccountLocked()).toBe(false);
    });

    it('should return true for locked account', () => {
      userSecurity.lockAccount('failed_attempts', 30);
      expect(userSecurity.isAccountLocked()).toBe(true);
    });

    it('should auto-unlock expired lock', () => {
      userSecurity.lockAccount('failed_attempts', 30);
      // Set lock expiry to past
      userSecurity.lockedUntil = new Date(Date.now() - 1000);
      
      const isLocked = userSecurity.isAccountLocked();
      
      expect(isLocked).toBe(false);
      expect(userSecurity.isLocked).toBe(false);
    });
  });

  describe('detectSuspiciousActivity', () => {
    beforeEach(async () => {
      // Add some login history
      userSecurity.knownIPs.push({
        ip: '192.168.1.1',
        firstSeen: new Date(),
        lastSeen: new Date(),
        loginCount: 5
      });
      
      userSecurity.knownDevices.push({
        fingerprint: userSecurity.generateDeviceFingerprint('Known Browser', '192.168.1.1'),
        userAgent: 'Known Browser',
        firstSeen: new Date(),
        lastSeen: new Date(),
        loginCount: 5
      });

      // Add recent successful logins
      for (let i = 0; i < 5; i++) {
        userSecurity.securityEvents.push({
          type: 'login_success',
          timestamp: new Date(Date.now() - (i * 60 * 1000)) // 1 minute apart
        });
      }
    });

    it('should detect suspicious activity for new IP and device', () => {
      const isSuspicious = userSecurity.detectSuspiciousActivity('10.0.0.1', 'New Browser');
      expect(isSuspicious).toBe(true);
    });

    it('should not detect suspicious activity for known IP and device', () => {
      const isSuspicious = userSecurity.detectSuspiciousActivity('192.168.1.1', 'Known Browser');
      expect(isSuspicious).toBe(false);
    });

    it('should not detect suspicious activity with few recent logins', () => {
      // Clear recent logins
      userSecurity.securityEvents = [];
      
      const isSuspicious = userSecurity.detectSuspiciousActivity('10.0.0.1', 'New Browser');
      expect(isSuspicious).toBe(false);
    });
  });

  describe('generateDeviceFingerprint', () => {
    it('should generate consistent fingerprint for same input', () => {
      const fingerprint1 = userSecurity.generateDeviceFingerprint('Chrome Browser', '192.168.1.1');
      const fingerprint2 = userSecurity.generateDeviceFingerprint('Chrome Browser', '192.168.1.1');
      
      expect(fingerprint1).toBe(fingerprint2);
      expect(typeof fingerprint1).toBe('string');
      expect(fingerprint1.length).toBe(64); // SHA256 hex length
    });

    it('should generate different fingerprints for different inputs', () => {
      const fingerprint1 = userSecurity.generateDeviceFingerprint('Chrome Browser', '192.168.1.1');
      const fingerprint2 = userSecurity.generateDeviceFingerprint('Firefox Browser', '192.168.1.1');
      
      expect(fingerprint1).not.toBe(fingerprint2);
    });
  });
});