const nodemailer = require('nodemailer');
const logger = require('../config/logger');

class EmailService {
  constructor() {
    this.transporter = null;
    this.initialize();
  }

  initialize() {
    try {
      // Configure transporter based on environment
      if (process.env.NODE_ENV === 'production') {
        // Production: Use SMTP service (Gmail, SendGrid, etc.)
        this.transporter = nodemailer.createTransporter({
          host: process.env.SMTP_HOST,
          port: process.env.SMTP_PORT || 587,
          secure: process.env.SMTP_SECURE === 'true',
          auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS
          }
        });
      } else {
        // Development: Use Ethereal Email for testing
        this.transporter = nodemailer.createTransporter({
          host: 'smtp.ethereal.email',
          port: 587,
          auth: {
            user: 'ethereal.user@ethereal.email',
            pass: 'ethereal.pass'
          }
        });
      }

      logger.info('Email service initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize email service:', error);
    }
  }

  async sendEmail(to, subject, html, text = null) {
    try {
      if (!this.transporter) {
        throw new Error('Email transporter not initialized');
      }

      const mailOptions = {
        from: process.env.FROM_EMAIL || 'noreply@authservice.com',
        to,
        subject,
        html,
        text: text || this.stripHtml(html)
      };

      const info = await this.transporter.sendMail(mailOptions);
      
      logger.info('Email sent successfully', {
        to,
        subject,
        messageId: info.messageId
      });

      return {
        success: true,
        messageId: info.messageId,
        previewUrl: process.env.NODE_ENV !== 'production' ? 
          nodemailer.getTestMessageUrl(info) : null
      };
    } catch (error) {
      logger.error('Failed to send email:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  async sendWelcomeEmail(user) {
    const subject = 'Welcome to Auth Service!';
    const html = this.getWelcomeTemplate(user);
    
    return await this.sendEmail(user.email, subject, html);
  }

  async sendVerificationEmail(user, verificationToken) {
    const subject = 'Verify Your Email Address';
    const verificationUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/verify?token=${verificationToken}&email=${encodeURIComponent(user.email)}`;
    const html = this.getVerificationTemplate(user, verificationUrl, verificationToken);
    
    return await this.sendEmail(user.email, subject, html);
  }

  async sendPasswordResetEmail(user, resetToken) {
    const subject = 'Password Reset Request';
    const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password?token=${resetToken}&email=${encodeURIComponent(user.email)}`;
    const html = this.getPasswordResetTemplate(user, resetUrl);
    
    return await this.sendEmail(user.email, subject, html);
  }

  async sendSecurityAlert(user, alertType, details = {}) {
    const subject = 'Security Alert - Auth Service';
    const html = this.getSecurityAlertTemplate(user, alertType, details);
    
    return await this.sendEmail(user.email, subject, html);
  }

  async sendAccountApprovalEmail(user) {
    const subject = 'Account Approved - Auth Service';
    const html = this.getAccountApprovalTemplate(user);
    
    return await this.sendEmail(user.email, subject, html);
  }

  async sendAccountLockEmail(user, reason, unlockTime) {
    const subject = 'Account Temporarily Locked - Auth Service';
    const html = this.getAccountLockTemplate(user, reason, unlockTime);
    
    return await this.sendEmail(user.email, subject, html);
  }

  // Email Templates
  getWelcomeTemplate(user) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Welcome to Auth Service</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #007bff; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f8f9fa; }
          .footer { padding: 20px; text-align: center; color: #666; font-size: 12px; }
          .button { display: inline-block; padding: 12px 24px; background: #007bff; color: white; text-decoration: none; border-radius: 4px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Welcome to Auth Service!</h1>
          </div>
          <div class="content">
            <h2>Hello ${user.email}!</h2>
            <p>Welcome to our authentication service. Your account has been created successfully with the role: <strong>${user.role}</strong>.</p>
            
            ${!user.isVerified ? `
              <p><strong>Next Steps:</strong></p>
              <ol>
                <li>Verify your email address using the verification link sent separately</li>
                ${user.role !== 'admin' ? '<li>Wait for admin approval to access all features</li>' : ''}
              </ol>
            ` : ''}
            
            <p>If you have any questions, please don't hesitate to contact our support team.</p>
          </div>
          <div class="footer">
            <p>&copy; 2024 Auth Service. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  getVerificationTemplate(user, verificationUrl, token) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Verify Your Email</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #28a745; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f8f9fa; }
          .footer { padding: 20px; text-align: center; color: #666; font-size: 12px; }
          .button { display: inline-block; padding: 12px 24px; background: #28a745; color: white; text-decoration: none; border-radius: 4px; margin: 10px 0; }
          .token { background: #e9ecef; padding: 10px; border-radius: 4px; font-family: monospace; word-break: break-all; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Verify Your Email Address</h1>
          </div>
          <div class="content">
            <h2>Hello ${user.email}!</h2>
            <p>Thank you for registering with Auth Service. To complete your registration, please verify your email address.</p>
            
            <p><a href="${verificationUrl}" class="button">Verify Email Address</a></p>
            
            <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p><a href="${verificationUrl}">${verificationUrl}</a></p>
            
            <p>Or use this verification token manually: <span class="token">${token}</span></p>
            
            <p><strong>This verification link will expire in 24 hours.</strong></p>
            
            <p>If you didn't create an account with us, please ignore this email.</p>
          </div>
          <div class="footer">
            <p>&copy; 2024 Auth Service. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  getPasswordResetTemplate(user, resetUrl) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Password Reset Request</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #ffc107; color: #212529; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f8f9fa; }
          .footer { padding: 20px; text-align: center; color: #666; font-size: 12px; }
          .button { display: inline-block; padding: 12px 24px; background: #ffc107; color: #212529; text-decoration: none; border-radius: 4px; margin: 10px 0; }
          .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; border-radius: 4px; margin: 10px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Password Reset Request</h1>
          </div>
          <div class="content">
            <h2>Hello ${user.email}!</h2>
            <p>We received a request to reset your password for your Auth Service account.</p>
            
            <p><a href="${resetUrl}" class="button">Reset Password</a></p>
            
            <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p><a href="${resetUrl}">${resetUrl}</a></p>
            
            <div class="warning">
              <strong>Security Notice:</strong>
              <ul>
                <li>This reset link will expire in 1 hour</li>
                <li>If you didn't request this reset, please ignore this email</li>
                <li>Your password will remain unchanged until you create a new one</li>
              </ul>
            </div>
          </div>
          <div class="footer">
            <p>&copy; 2024 Auth Service. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  getSecurityAlertTemplate(user, alertType, details) {
    const alertMessages = {
      'suspicious_login': 'Suspicious login activity detected',
      'new_device': 'New device login detected',
      'password_changed': 'Password changed successfully',
      'account_locked': 'Account temporarily locked',
      'multiple_failed_attempts': 'Multiple failed login attempts detected'
    };

    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Security Alert</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #dc3545; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f8f9fa; }
          .footer { padding: 20px; text-align: center; color: #666; font-size: 12px; }
          .alert { background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 4px; margin: 10px 0; }
          .details { background: #e9ecef; padding: 10px; border-radius: 4px; margin: 10px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔒 Security Alert</h1>
          </div>
          <div class="content">
            <h2>Hello ${user.email}!</h2>
            
            <div class="alert">
              <strong>${alertMessages[alertType] || 'Security event detected'}</strong>
            </div>
            
            <p>We detected security-related activity on your account:</p>
            
            <div class="details">
              <strong>Event Details:</strong><br>
              Time: ${new Date().toLocaleString()}<br>
              ${details.ipAddress ? `IP Address: ${details.ipAddress}<br>` : ''}
              ${details.userAgent ? `Device: ${details.userAgent}<br>` : ''}
              ${details.location ? `Location: ${details.location}<br>` : ''}
            </div>
            
            <p><strong>What should you do?</strong></p>
            <ul>
              <li>If this was you, no action is needed</li>
              <li>If this wasn't you, please change your password immediately</li>
              <li>Consider enabling two-factor authentication for added security</li>
              <li>Contact support if you need assistance</li>
            </ul>
          </div>
          <div class="footer">
            <p>&copy; 2024 Auth Service. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  getAccountApprovalTemplate(user) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Account Approved</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #28a745; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f8f9fa; }
          .footer { padding: 20px; text-align: center; color: #666; font-size: 12px; }
          .button { display: inline-block; padding: 12px 24px; background: #28a745; color: white; text-decoration: none; border-radius: 4px; margin: 10px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🎉 Account Approved!</h1>
          </div>
          <div class="content">
            <h2>Hello ${user.email}!</h2>
            <p>Great news! Your account has been approved by our administrators.</p>
            
            <p>You now have full access to all features available for your role: <strong>${user.role}</strong></p>
            
            <p><a href="${process.env.FRONTEND_URL || 'http://localhost:3000'}/login" class="button">Login to Your Account</a></p>
            
            <p>Thank you for your patience during the approval process.</p>
          </div>
          <div class="footer">
            <p>&copy; 2024 Auth Service. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  getAccountLockTemplate(user, reason, unlockTime) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Account Temporarily Locked</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #ffc107; color: #212529; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f8f9fa; }
          .footer { padding: 20px; text-align: center; color: #666; font-size: 12px; }
          .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 4px; margin: 10px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>⚠️ Account Temporarily Locked</h1>
          </div>
          <div class="content">
            <h2>Hello ${user.email}!</h2>
            
            <div class="warning">
              <strong>Your account has been temporarily locked for security reasons.</strong>
            </div>
            
            <p><strong>Reason:</strong> ${this.getLockReasonMessage(reason)}</p>
            <p><strong>Unlock Time:</strong> ${unlockTime ? new Date(unlockTime).toLocaleString() : 'Contact support'}</p>
            
            <p><strong>What happened?</strong></p>
            <p>${this.getLockReasonExplanation(reason)}</p>
            
            <p><strong>What can you do?</strong></p>
            <ul>
              <li>Wait for the automatic unlock time</li>
              <li>Contact support if you believe this is an error</li>
              <li>Ensure you're using the correct login credentials</li>
            </ul>
          </div>
          <div class="footer">
            <p>&copy; 2024 Auth Service. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  getLockReasonMessage(reason) {
    const messages = {
      'failed_attempts': 'Too many failed login attempts',
      'suspicious_activity': 'Suspicious activity detected',
      'admin_action': 'Administrative action',
      'security_breach': 'Security breach prevention'
    };
    return messages[reason] || 'Security precaution';
  }

  getLockReasonExplanation(reason) {
    const explanations = {
      'failed_attempts': 'Multiple incorrect password attempts were detected on your account.',
      'suspicious_activity': 'Unusual login patterns or suspicious activity was detected.',
      'admin_action': 'An administrator has temporarily restricted access to your account.',
      'security_breach': 'As a precautionary measure due to potential security concerns.'
    };
    return explanations[reason] || 'Your account was locked as a security precaution.';
  }

  stripHtml(html) {
    return html.replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
  }
}

module.exports = new EmailService();