const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const path = require('path');

// Define log levels
const levels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

// Define colors for each level
const colors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'white',
};

// Tell winston that you want to link the colors
winston.addColors(colors);

// Define log format
const format = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
  winston.format.colorize({ all: true }),
  winston.format.printf(
    (info) => `${info.timestamp} ${info.level}: ${info.message}`,
  ),
);

// Define which transports the logger must use
const transports = [
  // Console transport
  new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }),
  
  // Error log file
  new DailyRotateFile({
    filename: path.join('logs', 'error-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    level: 'error',
    handleExceptions: true,
    json: true,
    maxSize: '20m',
    maxFiles: '14d',
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.json()
    )
  }),
  
  // Combined log file
  new DailyRotateFile({
    filename: path.join('logs', 'combined-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    json: true,
    maxSize: '20m',
    maxFiles: '14d',
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.json()
    )
  }),
  
  // HTTP requests log
  new DailyRotateFile({
    filename: path.join('logs', 'http-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    level: 'http',
    json: true,
    maxSize: '20m',
    maxFiles: '14d',
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.json()
    )
  })
];

// Create the logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  levels,
  format,
  transports,
  exitOnError: false,
});

// Create logs directory if it doesn't exist
const fs = require('fs');
const logsDir = 'logs';
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir);
}

module.exports = logger;