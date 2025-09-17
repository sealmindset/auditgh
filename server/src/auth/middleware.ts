import { Request, Response, NextFunction } from 'express';
import { config } from '../config/env.js';

export type SessionUser = {
  id?: string;
  email?: string;
  displayName?: string;
  roles: ('reader'|'project_admin'|'super_admin')[];
  devBypass?: boolean;
};

declare module 'express-session' {
  interface SessionData {
    user?: SessionUser;
  }
}

export function attachDevBypass(_req: Request, _res: Response, next: NextFunction) {
  if (config.authDisabled) {
    // Inject a fake super_admin session
    (_req.session as any).user = {
      id: '00000000-0000-0000-0000-000000000000',
      email: 'dev@example.com',
      displayName: 'Dev Super Admin',
      roles: ['super_admin'],
      devBypass: true,
    };
  }
  next();
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (config.authDisabled && req.session?.user) return next();
  if (!req.session?.user) return res.status(401).json({ error: { code: 'unauthorized', message: 'Login required' } });
  next();
}

export function requireRole(role: 'reader'|'project_admin'|'super_admin') {
  return (req: Request, res: Response, next: NextFunction) => {
    const roles = req.session?.user?.roles || [];
    if (config.authDisabled) return next();
    if (!roles.includes(role) && !roles.includes('super_admin')) {
      return res.status(403).json({ error: { code: 'forbidden', message: 'Insufficient role' } });
    }
    next();
  };
}
