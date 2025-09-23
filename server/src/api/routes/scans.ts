import { Router } from 'express';
import { requireAuth, requireRole } from '../../auth/middleware.js';
import { createScanSchema } from '../validators/scans.js';
import { createScan, getScan, listRecentScans, updateScanStatus } from '../../db/repositories/scans.js';
import { scanRunner } from '../../scans/runner.js';

export const scansRouter = Router();

// List recent scans
scansRouter.get('/', requireAuth, async (_req, res, next) => {
  try {
    const data = await listRecentScans(50);
    res.json({ data });
  } catch (err) { next(err); }
});

// Get scan by id
scansRouter.get('/:id', requireAuth, async (req, res, next) => {
  try {
    const item = await getScan(req.params.id);
    if (!item) return res.status(404).json({ error: { code: 'not_found', message: 'Scan not found' } });
    res.json({ data: item });
  } catch (err) { next(err); }
});

// Create and start a scan
scansRouter.post('/', requireAuth, async (req, res, next) => {
  try {
    const parsed = createScanSchema.parse(req.body);
    const created = await createScan({ project_id: parsed.project_id, profile: parsed.profile || null });
    // Fire and forget the in-memory/real runner
    // eslint-disable-next-line no-void
    void scanRunner.start(created, {
      profile: parsed.profile || null,
      scanners: parsed.scanners,
      scope: parsed.scope,
      repo: parsed.repo,
      codeql_languages: (parsed as any).codeql_languages,
      codeql_skip_autobuild: (parsed as any).codeql_skip_autobuild,
      codeql_recreate_db: (parsed as any).codeql_recreate_db,
    });
    res.status(201).json({ data: created });
  } catch (err: any) {
    if (err?.name === 'ZodError') return res.status(422).json({ error: { code: 'validation_failed', issues: err.issues } });
    next(err);
  }
});

// SSE stream for logs/progress
scansRouter.get('/:id/stream', requireAuth, async (req, res, _next) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  const scanId = req.params.id;

  // heartbeat to keep the connection alive on proxies
  const hb = setInterval(() => {
    res.write(': ping\n\n');
  }, 15000);

  scanRunner.subscribe(scanId, res);

  req.on('close', () => {
    clearInterval(hb);
    scanRunner.unsubscribe(scanId, res);
    res.end();
  });
});

// Cancel (Phase 1 stub)
scansRouter.post('/:id/cancel', requireRole('project_admin'), async (req, res, next) => {
  try {
    const id = req.params.id;
    scanRunner.cancel(id);
    const updated = await updateScanStatus(id, 'canceled', { finished_at: new Date() });
    if (!updated) return res.status(404).json({ error: { code: 'not_found', message: 'Scan not found' } });
    res.json({ data: updated });
  } catch (err) { next(err); }
});
