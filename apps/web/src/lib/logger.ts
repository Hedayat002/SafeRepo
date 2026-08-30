import pino from 'pino';

/**
 * Structured logger using Pino.
 *
 * - JSON format in production
 * - Pretty-print in development
 * - PII fields are redacted
 * - No console.log anywhere in the codebase
 */

const isProduction = process.env.NODE_ENV === 'production';
const isTest = process.env.NODE_ENV === 'test';

export const logger = pino({
  level: isTest ? 'silent' : isProduction ? 'info' : 'debug',
  redact: {
    paths: ['email', '*.email', 'req.headers.cookie', 'req.headers.authorization'],
    censor: '[REDACTED]',
  },
  ...(isProduction
    ? {}
    : {
        transport: {
          target: 'pino-pretty',
          options: {
            colorize: true,
            translateTime: 'SYS:standard',
            ignore: 'pid,hostname',
          },
        },
      }),
});
