const { createLogger, format, transports } = require('winston');
const path = require('path');

const logger = createLogger({
  level: 'info',
  format: format.combine(
    format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    format.printf(({ timestamp, level, message, meta }) => {
      const m = meta ? ` ${JSON.stringify(meta)}` : '';
      return `${timestamp} ${level.toUpperCase()}: ${message}${m}`;
    })
  ),
  transports: [
    new transports.Console(),
    new transports.File({
      filename: path.resolve(__dirname, '../logs/auth.log'),
      level: 'info',
    }),
    new transports.File({
      filename: path.resolve(__dirname, '../logs/error.log'),
      level: 'error',
    }),
  ],
});

module.exports = logger;
