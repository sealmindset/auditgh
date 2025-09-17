import { randomUUID } from 'crypto';
import { Handler } from 'express';

export const requestId: Handler = (req, res, next) => {
  const existing = req.header('X-Request-ID') || req.header('x-request-id');
  const id = existing || randomUUID();
  res.setHeader('X-Request-ID', id);
  (req as any).requestId = id;
  next();
};
