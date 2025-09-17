import { Router } from 'express';
import { pingDb } from '../../db/pool.js';
import { config } from '../../config/env.js';
import { Issuer } from 'openid-client';

export const healthRouter = Router();

healthRouter.get('/db', async (_req, res) => {
  const ok = await pingDb();
  res.json({ ok });
});

healthRouter.get('/redis', async (_req, res) => {
  const ok = !!config.redisUrl; // basic indicator; detailed ping added later
  res.json({ ok, url: config.redisUrl || null });
});

healthRouter.get('/oidc', async (_req, res) => {
  if (!config.oidc.issuer) return res.json({ ok: false, error: 'no_issuer' });
  try {
    const issuer = await Issuer.discover(config.oidc.issuer);
    res.json({ ok: !!issuer?.issuer });
  } catch (e: any) {
    res.json({ ok: false, error: e?.message || 'discover_failed' });
  }
});
