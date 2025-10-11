const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const UserSecurity = require('../models/UserSecurity');
const RefreshToken = require('../models/RefreshToken');
const { generateToken } = require('../utils/jwt');
const TokenUtils = require('../utils/tokenUtils');
const emailService = require('../services/emailService');
const { authenticate, authorize, requireVerification, requireApproval } = require('../middleware/auth');
const { auditLoggers, createAuditLog } = require('../middleware/auditLogger');
const logger = require('../config/logger');

const router = express.Router();

// Validation middleware
const validateSignup = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long'),
  body('role')
    .isIn(['school', 'teacher', 'vendor', 'admin'])
    .withMessage('Role must be one of: school, teacher, vendor, admin')
];

const validateLogin = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
];

// @route   POST /api/auth/signup
// @desc    Register a new user
// @access  Public
router.post('/signup', validateSignup, auditLoggers.signup, async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Signup validation failed', { 
        errors: errors.array(),
        email: req.body.email,
        ip: req.ip 
      });
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { email, password, role } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      logger.warn('Signup attempt with existing email', { 
        email,
        ip: req.ip 
      });
      return res.status(400).json({
        success: false,
        message: 'User already exists with this email'
      });
    }

    // Create new user
    const user = new User({
      email,
      passwordHash: password, // Will be hashed by pre-save middleware
      role,
      isVerified: false,
      approvedByAdmin: role === 'admin' ? true : false // Auto-approve admin accounts
    });

    // Generate verification token
    const verificationToken = user.generateVerificationToken();
    
    await user.save();

    // Create user security record
    const userSecurity = new UserSecurity({
      userId: user._id,
      userEmail: user.email
    });
    await userSecurity.save();

    logger.info('User registered successfully', {
      userId: user._id,
      email: user.email,
      role: user.role,
      ip: req.ip
    });

    // Generate token pair
    const deviceFingerprint = TokenUtils.generateDeviceFingerprint(
      req.get('User-Agent'),
      req.ip
    );

    const tokenPair = await TokenUtils.generateTokenPair(user, {
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      deviceFingerprint
    });

    // Send welcome and verification emails
    try {
      await emailService.sendWelcomeEmail(user);
      await emailService.sendVerificationEmail(user, verificationToken);
    } catch (emailError) {
      logger.warn('Failed to send signup emails:', emailError);
      // Don't fail the signup if email fails
    }

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        user,
        ...tokenPair,
        verificationToken // In production, send this via email
      }
    });

  } catch (error) {
    logger.error('Signup error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during registration'
    });
  }
});

// @route   POST /api/auth/login
// @desc    Authenticate user and get token
// @access  Public
router.post('/login', validateLogin, auditLoggers.login, async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Login validation failed', { 
        errors: errors.array(),
        email: req.body.email,
        ip: req.ip 
      });
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { email, password } = req.body;

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      logger.warn('Login attempt with non-existent email', { 
        email,
        ip: req.ip 
      });
      
      // Create audit log for failed login
      await createAuditLog('USER_LOGIN_FAILED', {
        userEmail: email,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl,
        method: req.method,
        success: false,
        errorMessage: 'Invalid credentials'
      });
      
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Get or create user security record
    let userSecurity = await UserSecurity.findOne({ userId: user._id });
    if (!userSecurity) {
      userSecurity = new UserSecurity({
        userId: user._id,
        userEmail: user.email
      });
    }

    // Check if account is locked
    if (userSecurity.isAccountLocked()) {
      logger.warn('Login attempt on locked account', {
        userId: user._id,
        email,
        lockReason: userSecurity.lockReason,
        lockedUntil: userSecurity.lockedUntil,
        ip: req.ip
      });

      return res.status(423).json({
        success: false,
        message: 'Account is temporarily locked',
        lockedUntil: userSecurity.lockedUntil
      });
    }

    // Check password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      logger.warn('Login attempt with invalid password', { 
        userId: user._id,
        email,
        ip: req.ip 
      });
      
      // Record failed login attempt
      await userSecurity.recordLoginAttempt(false, req.ip, req.get('User-Agent'));
      
      // Create audit log for failed login
      await createAuditLog('USER_LOGIN_FAILED', {
        userId: user._id,
        userEmail: email,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl,
        method: req.method,
        success: false,
        errorMessage: 'Invalid credentials'
      });
      
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Check for suspicious activity
    const isSuspicious = userSecurity.detectSuspiciousActivity(req.ip, req.get('User-Agent'));
    if (isSuspicious) {
      logger.warn('Suspicious login activity detected', {
        userId: user._id,
        email,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      // Send security alert email
      try {
        await emailService.sendSecurityAlert(user, 'suspicious_login', {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          timestamp: new Date()
        });
      } catch (emailError) {
        logger.warn('Failed to send security alert email:', emailError);
      }
    }

    // Record successful login
    await userSecurity.recordLoginAttempt(true, req.ip, req.get('User-Agent'));

    logger.info('User logged in successfully', {
      userId: user._id,
      email: user.email,
      role: user.role,
      ip: req.ip
    });

    // Generate token pair
    const deviceFingerprint = TokenUtils.generateDeviceFingerprint(
      req.get('User-Agent'),
      req.ip
    );

    const tokenPair = await TokenUtils.generateTokenPair(user, {
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      deviceFingerprint
    });

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user,
        ...tokenPair
      }
    });

  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during login'
    });
  }
});

// @route   POST /api/auth/verify
// @desc    Verify user email with token
// @access  Public
router.post('/verify', auditLoggers.emailVerification, async (req, res) => {
  try {
    const { email, verificationToken } = req.body;

    if (!email || !verificationToken) {
      logger.warn('Email verification attempt with missing data', { 
        email,
        hasToken: !!verificationToken,
        ip: req.ip 
      });
      return res.status(400).json({
        success: false,
        message: 'Email and verification token are required'
      });
    }

    // Find user by email and verification token
    const user = await User.findOne({ 
      email, 
      verificationToken 
    });

    if (!user) {
      logger.warn('Email verification failed - invalid token or email', { 
        email,
        ip: req.ip 
      });
      
      // Create audit log for failed verification
      await createAuditLog('EMAIL_VERIFICATION_FAILED', {
        userEmail: email,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl,
        method: req.method,
        success: false,
        errorMessage: 'Invalid verification token or email'
      });
      
      return res.status(400).json({
        success: false,
        message: 'Invalid verification token or email'
      });
    }

    // Update user verification status
    user.isVerified = true;
    user.verificationToken = null;
    await user.save();

    logger.info('Email verified successfully', {
      userId: user._id,
      email: user.email,
      ip: req.ip
    });

    res.json({
      success: true,
      message: 'Email verified successfully',
      data: {
        user
      }
    });

  } catch (error) {
    logger.error('Verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during verification'
    });
  }
});

// @route   POST /api/auth/refresh
// @desc    Refresh access token using refresh token
// @access  Public
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: 'Refresh token is required'
      });
    }

    const deviceFingerprint = TokenUtils.generateDeviceFingerprint(
      req.get('User-Agent'),
      req.ip
    );

    const result = await TokenUtils.refreshAccessToken(refreshToken, {
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      deviceFingerprint
    });

    logger.info('Token refreshed successfully', {
      userId: result.user._id,
      email: result.user.email,
      ip: req.ip
    });

    res.json({
      success: true,
      message: 'Token refreshed successfully',
      data: {
        user: result.user,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        expiresIn: result.expiresIn
      }
    });

  } catch (error) {
    logger.error('Token refresh error:', error);
    
    // Different error responses based on error type
    if (error.message.includes('reuse detected')) {
      return res.status(403).json({
        success: false,
        message: 'Security violation detected. Please login again.'
      });
    }

    res.status(401).json({
      success: false,
      message: 'Invalid or expired refresh token'
    });
  }
});

// @route   POST /api/auth/logout
// @desc    Logout user and revoke refresh token
// @access  Private
router.post('/logout', authenticate, async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (refreshToken) {
      await TokenUtils.revokeRefreshToken(refreshToken, 'user', 'User logout');
    }

    logger.info('User logged out', {
      userId: req.user._id,
      email: req.user.email,
      ip: req.ip
    });

    res.json({
      success: true,
      message: 'Logged out successfully'
    });

  } catch (error) {
    logger.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during logout'
    });
  }
});

// @route   POST /api/auth/logout-all
// @desc    Logout from all devices
// @access  Private
router.post('/logout-all', authenticate, async (req, res) => {
  try {
    await TokenUtils.revokeAllUserTokens(req.user._id, 'user', 'Logout from all devices');

    logger.info('User logged out from all devices', {
      userId: req.user._id,
      email: req.user.email,
      ip: req.ip
    });

    res.json({
      success: true,
      message: 'Logged out from all devices successfully'
    });

  } catch (error) {
    logger.error('Logout all error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during logout'
    });
  }
});

// @route   GET /api/auth/sessions
// @desc    Get user's active sessions
// @access  Private
router.get('/sessions', authenticate, async (req, res) => {
  try {
    const sessions = await TokenUtils.getUserActiveTokens(req.user._id);

    // Format sessions for frontend
    const formattedSessions = sessions.map(session => ({
      id: session._id,
      family: session.family,
      createdAt: session.createdAt,
      lastUsedAt: session.lastUsedAt,
      ipAddress: session.ipAddress,
      userAgent: session.userAgent,
      isCurrent: session.family === req.body.currentFamily // If provided
    }));

    res.json({
      success: true,
      data: {
        sessions: formattedSessions,
        total: formattedSessions.length
      }
    });

  } catch (error) {
    logger.error('Get sessions error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while fetching sessions'
    });
  }
});

// @route   GET /api/auth/me
// @desc    Get current user profile
// @access  Private
router.get('/me', authenticate, auditLoggers.profileUpdate, async (req, res) => {
  try {
    logger.info('User profile accessed', {
      userId: req.user._id,
      email: req.user.email,
      ip: req.ip
    });
    
    res.json({
      success: true,
      data: {
        user: req.user
      }
    });
  } catch (error) {
    logger.error('Get profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while fetching profile'
    });
  }
});

// @route   PUT /api/auth/approve/:id
// @desc    Admin approves user account
// @access  Private (Admin only)
router.put('/approve/:id', authenticate, authorize('admin'), auditLoggers.adminApproval, async (req, res) => {
  try {
    const { id } = req.params;

    // Find user by ID
    const user = await User.findById(id);
    if (!user) {
      logger.warn('Admin approval attempt for non-existent user', { 
        targetUserId: id,
        adminId: req.user._id,
        ip: req.ip 
      });
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Update approval status
    user.approvedByAdmin = true;
    await user.save();

    // Send approval email
    try {
      await emailService.sendAccountApprovalEmail(user);
    } catch (emailError) {
      logger.warn('Failed to send approval email:', emailError);
    }

    logger.info('User approved by admin', {
      targetUserId: user._id,
      targetUserEmail: user.email,
      adminId: req.user._id,
      adminEmail: req.user.email,
      ip: req.ip
    });

    res.json({
      success: true,
      message: 'User approved successfully',
      data: {
        user
      }
    });

  } catch (error) {
    logger.error('Approval error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during approval'
    });
  }
});

// @route   GET /api/auth/users
// @desc    Get all users (Admin only)
// @access  Private (Admin only)
router.get('/users', authenticate, authorize('admin'), auditLoggers.profileUpdate, async (req, res) => {
  try {
    const { page = 1, limit = 10, role, isVerified, approvedByAdmin } = req.query;
    
    // Build filter object
    const filter = {};
    if (role) filter.role = role;
    if (isVerified !== undefined) filter.isVerified = isVerified === 'true';
    if (approvedByAdmin !== undefined) filter.approvedByAdmin = approvedByAdmin === 'true';

    const users = await User.find(filter)
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .sort({ createdAt: -1 });

    const total = await User.countDocuments(filter);

    logger.info('Admin accessed users list', {
      adminId: req.user._id,
      adminEmail: req.user.email,
      filters: filter,
      resultCount: users.length,
      ip: req.ip
    });

    res.json({
      success: true,
      data: {
        users,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      }
    });

  } catch (error) {
    logger.error('Get users error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while fetching users'
    });
  }
});

module.exports = router;