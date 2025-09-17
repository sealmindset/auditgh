import { Router } from 'express';
import { config } from '../config/env.js';
import { attachDevBypass } from './middleware.js';

export const authRouter = Router();

authRouter.use(attachDevBypass);

authRouter.get('/me', (req, res) => {
  const user = req.session?.user || null;
  res.json({ authenticated: !!user, user, authDisabled: config.authDisabled });
});

authRouter.get('/login', (_req, res) => {
  if (config.authDisabled) return res.redirect('/');
  // OIDC flow will be implemented in Phase 2
  return res.status(501).json({ error: { code: 'not_implemented', message: 'OIDC not enabled in this phase' } });
});

authRouter.get('/callback', (_req, res) => {
  return res.status(501).json({ error: { code: 'not_implemented', message: 'OIDC callback not enabled in this phase' } });
});

authRouter.post('/logout', (req, res) => {
  req.session?.destroy(() => res.json({ ok: true }));
});
