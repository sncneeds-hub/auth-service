const logger = require('../config/logger');

// Request logging middleware
const requestLogger = (req, res, next) => {
  const startTime = Date.now();
  
  // Get client IP
  const clientIP = req.ip || 
                   req.connection.remoteAddress || 
                   req.socket.remoteAddress ||
                   (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
                   req.headers['x-forwarded-for']?.split(',')[0] ||
                   req.headers['x-real-ip'] ||
                   'unknown';

  // Log the incoming request
  logger.http(`${req.method} ${req.originalUrl} - IP: ${clientIP} - User-Agent: ${req.get('User-Agent') || 'unknown'}`);

  // Override res.end to log response
  const originalEnd = res.end;
  res.end = function(chunk, encoding) {
    const endTime = Date.now();
    const duration = endTime - startTime;
    
    // Log the response
    const logLevel = res.statusCode >= 400 ? 'warn' : 'http';
    logger[logLevel](`${req.method} ${req.originalUrl} - ${res.statusCode} - ${duration}ms - IP: ${clientIP}`, {
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      ip: clientIP,
      userAgent: req.get('User-Agent'),
      userId: req.user?._id || null,
      userEmail: req.user?.email || null
    });

    // Call the original end method
    originalEnd.call(this, chunk, encoding);
  };

  next();
};

module.exports = requestLogger;