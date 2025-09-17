import { NextFunction, Request, Response } from 'express';
import { logger } from '../config/logging.js';

export function errorHandler(err: any, _req: Request, res: Response, _next: NextFunction) {
  const status = err.status || err.statusCode || 500;
  const code = err.code || 'internal_error';
  const message = status >= 500 ? 'Internal Server Error' : (err.message || 'Bad Request');
  logger.error({ err, code, status }, 'Request error');
  res.status(status).json({ error: { code, message } });
}
