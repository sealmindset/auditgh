import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import csrf from 'csurf';
import type { Express, Request, Response, NextFunction } from 'express';
import { config } from './env.js';

export function applySecurity(app: Express) {
  app.use(helmet());
  app.use(cors({ origin: '*', credentials: false }));

  const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 300,
    standardHeaders: true,
    legacyHeaders: false,
  });
  app.use(limiter);

  // CSRF: enable only when auth is enabled; in dev bypass we skip CSRF to ease Phase 1
  if (!config.authDisabled) {
    const csrfProtection = csrf({ cookie: true });
    app.use((req: Request, res: Response, next: NextFunction) => {
      if (req.method === 'GET') return next();
      if (req.path.startsWith('/scans/') && req.path.endsWith('/stream')) return next();
      return csrfProtection(req as any, res as any, next as any);
    });
  }
}
