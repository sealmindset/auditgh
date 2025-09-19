import pino from 'pino';
import pinoHttpImport from 'pino-http';

export const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers.cookie',
      'res.headers["set-cookie"]',
      'password',
      'client_secret',
      '*.secret',
      '*.token',
    ],
    remove: true,
  },
});

// Under NodeNext module resolution the pino-http import type can be ambiguous; cast to callable
const pinoHttp = (pinoHttpImport as unknown as (opts?: any) => any);
export const httpLogger = pinoHttp({
  logger,
  customAttributeKeys: {
    req: 'request',
    res: 'response',
  },
});
