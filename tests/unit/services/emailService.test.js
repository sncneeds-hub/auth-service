const emailService = require('../../../services/emailService');

// Mock nodemailer
jest.mock('nodemailer', () => ({
  createTransporter: jest.fn(() => ({
    sendMail: jest.fn(),
    verify: jest.fn()
  }))
}));

describe('Email Service', () => {
  const mockUser = {
    _id: '507f1f77bcf86cd799439011',
    email: 'test@example.com',
    role: 'teacher'
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('sendEmail', () => {
    it('should send email successfully', async () => {
      const mockTransporter = {
        sendMail: jest.fn().mockResolvedValue({
          messageId: 'test-message-id'
        })
      };
      
      emailService.transporter = mockTransporter;

      const result = await emailService.sendEmail(
        'test@example.com',
        'Test Subject',
        '<h1>Test HTML</h1>'
      );

      expect(result.success).toBe(true);
      expect(result.messageId).toBe('test-message-id');
      expect(mockTransporter.sendMail).toHaveBeenCalledWith({
        from: 'noreply@authservice.com',
        to: 'test@example.com',
        subject: 'Test Subject',
        html: '<h1>Test HTML</h1>',
        text: 'Test HTML'
      });
    });

    it('should handle email sending errors', async () => {
      const mockTransporter = {
        sendMail: jest.fn().mockRejectedValue(new Error('SMTP Error'))
      };
      
      emailService.transporter = mockTransporter;

      const result = await emailService.sendEmail(
        'test@example.com',
        'Test Subject',
        '<h1>Test HTML</h1>'
      );

      expect(result.success).toBe(false);
      expect(result.error).toBe('SMTP Error');
    });
  });

  describe('sendWelcomeEmail', () => {
    it('should send welcome email with correct content', async () => {
      const mockSendEmail = jest.spyOn(emailService, 'sendEmail')
        .mockResolvedValue({ success: true, messageId: 'test-id' });

      const result = await emailService.sendWelcomeEmail(mockUser);

      expect(result.success).toBe(true);
      expect(mockSendEmail).toHaveBeenCalledWith(
        mockUser.email,
        'Welcome to Auth Service!',
        expect.stringContaining('Welcome to Auth Service!')
      );
    });
  });

  describe('sendVerificationEmail', () => {
    it('should send verification email with token', async () => {
      const mockSendEmail = jest.spyOn(emailService, 'sendEmail')
        .mockResolvedValue({ success: true, messageId: 'test-id' });

      const verificationToken = 'test-verification-token';
      const result = await emailService.sendVerificationEmail(mockUser, verificationToken);

      expect(result.success).toBe(true);
      expect(mockSendEmail).toHaveBeenCalledWith(
        mockUser.email,
        'Verify Your Email Address',
        expect.stringContaining(verificationToken)
      );
    });
  });

  describe('sendSecurityAlert', () => {
    it('should send security alert email', async () => {
      const mockSendEmail = jest.spyOn(emailService, 'sendEmail')
        .mockResolvedValue({ success: true, messageId: 'test-id' });

      const alertDetails = {
        ipAddress: '192.168.1.1',
        userAgent: 'Test Browser',
        timestamp: new Date()
      };

      const result = await emailService.sendSecurityAlert(
        mockUser, 
        'suspicious_login', 
        alertDetails
      );

      expect(result.success).toBe(true);
      expect(mockSendEmail).toHaveBeenCalledWith(
        mockUser.email,
        'Security Alert - Auth Service',
        expect.stringContaining('Security Alert')
      );
    });
  });
});