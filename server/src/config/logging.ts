import pino from 'pino';
import pinoHttp from 'pino-http';

export const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers.cookie',
      'res.headers.set-cookie',
      'password',
      'client_secret',
      '*.secret',
      '*.token',
    ],
    remove: true,
  },
});

export const httpLogger = pinoHttp({
  logger,
  customAttributeKeys: {
    req: 'request',
    res: 'response',
  },
});
