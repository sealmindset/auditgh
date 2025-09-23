import { Router } from 'express';
import { requireAuth, requireRole } from '../../auth/middleware.js';
import { createProject, listProjects, getProject } from '../../db/repositories/projects.js';
import { getLatestScanByProject, listRecentScansByProject } from '../../db/repositories/scans.js';
import { getCodeqlFindings } from '../lib/codeql_findings.js';
import { listFindingsByProjectLatest } from '../../db/repositories/codeql_findings.js';
import { pool } from '../../db/pool.js';
import fs from 'fs';
import path from 'path';
import { config } from '../../config/env.js';
import { createProjectSchema } from '../validators/projects.js';

export const projectsRouter = Router();

projectsRouter.get('/', requireAuth, async (_req, res, next) => {
  try {
    const data = await listProjects();
    res.json({ data });
  } catch (err) { next(err); }
});

// List repos with CodeQL artifacts for this project from recent scans
projectsRouter.get('/:id/codeql/repos', requireAuth, async (req, res, next) => {
  try {
    const projectId = req.params.id;
    // DB-first: list distinct repos from recent codeql_scan_repos
    try {
      const { rows } = await pool.query<{repo_short:string}>(
        `select distinct repo_short from codeql_scan_repos where project_id = $1 order by repo_short asc`,
        [projectId]
      );
      if (rows && rows.length) {
        return res.json({ data: rows.map(r => r.repo_short) });
      }
    } catch {}
    // Fallback to filesystem scan of recent runs
    const recent = await listRecentScansByProject(projectId, 10);
    const found = new Set<string>();

    for (const s of recent) {
      // Resolve run directory; prefer configured workspace, fallback to server container mount
      let runDir = path.resolve(config.auditWorkspaceDir, s.id);
      if (!fs.existsSync(runDir)) {
        const alt = path.resolve('/workspace/runs', s.id);
        if (fs.existsSync(alt)) runDir = alt;
      }
      if (!fs.existsSync(runDir)) continue;
      // Enumerate repo subdirectories
      let entries: fs.Dirent[] = [];
      try { entries = fs.readdirSync(runDir, { withFileTypes: true }); } catch { entries = []; }
      for (const e of entries) {
        if (!e.isDirectory()) continue;
        const repoShort = e.name;
        const repoDir = path.join(runDir, repoShort);
        try {
          const files = fs.readdirSync(repoDir);
          const hasSarif = files.some(f => f.endsWith('.sarif') && f.startsWith(`${repoShort}_codeql_`));
          const hasMd = files.includes(`${repoShort}_codeql.md`);
          if (hasSarif || hasMd) found.add(repoShort);
        } catch { /* ignore */ }
      }
    }

    res.json({ data: Array.from(found.values()).sort() });
  } catch (err) { next(err); }
});

// CodeQL severity totals for latest scan in this project (DB-first)
projectsRouter.get('/:id/codeql/severity-totals', requireAuth, async (req, res, next) => {
  try {
    const projectId = req.params.id;
    const repoParam = (req.query.repo as string) || '';
    let repoShort = '';
    if (repoParam) {
      repoShort = (repoParam.includes('/') ? repoParam.split('/').pop() as string : repoParam).trim();
    } else {
      const proj = await getProject(projectId);
      if (proj?.repo_url) {
        try {
          const u = new URL(proj.repo_url);
          const parts = u.pathname.replace(/^\//,'').split('/');
          if (parts.length >= 2) repoShort = parts[1];
        } catch {}
      }
    }
    if (!repoShort) {
      return res.json({ data: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 } });
    }

    // Latest scan id by most recent created_at among findings for this project+repo
    const latestSql = `select scan_id, max(created_at) as max_created
                       from codeql_findings where project_id = $1 and repo_short = $2
                       group by scan_id order by max_created desc limit 1`;
    const { rows: head } = await pool.query<{scan_id: string}>(latestSql, [projectId, repoShort]);
    if (!head.length) {
      return res.json({ data: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 } });
    }
    const scanId = head[0].scan_id;
    const countsSql = `select lower(severity) as severity, count(*)::int as cnt
                       from codeql_findings where project_id = $1 and repo_short = $2 and scan_id = $3
                       group by lower(severity)`;
    const { rows } = await pool.query<{severity: string; cnt: number}>(countsSql, [projectId, repoShort, scanId]);
    const totals = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 } as Record<string, number>;
    for (const r of rows) {
      const key = (r.severity || 'unknown').toLowerCase();
      if (typeof totals[key] === 'number') totals[key] = r.cnt;
      else totals.unknown += r.cnt;
      totals.total += r.cnt;
    }
    res.json({ data: totals });
  } catch (err) { next(err); }
});

// Latest CodeQL findings for this project (derived from latest successful scan)
projectsRouter.get('/:id/codeql/findings', requireAuth, async (req, res, next) => {
  try {
    const projectId = req.params.id;
    const repoParam = (req.query.repo as string) || '';
    const lang = (req.query.lang as string) || '';
    const search = ((req.query.search as string) || '').toLowerCase();
    const sevQ = (req.query.severity as string) || '';
    const severityFilter = sevQ ? sevQ.split(',').map(s => s.trim().toLowerCase()).filter(Boolean) : [];
    const limit = Math.min(parseInt((req.query.limit as string) || '50', 10) || 50, 200);
    const offset = parseInt((req.query.offset as string) || '0', 10) || 0;
    const sort = ((req.query.sort as string) || 'severity').toLowerCase() as 'severity'|'rule'|'file'|'line';
    const dir = ((req.query.dir as string) || 'desc').toLowerCase() === 'asc' ? 'asc' : 'desc';

    const proj = await getProject(projectId);
    if (!proj) return res.status(404).json({ error: { code: 'not_found', message: 'Project not found' } });
    let targetScan = await getLatestScanByProject(projectId);
    if (!targetScan) return res.json({ data: { items: [], total: 0 } });

    const repo = repoParam || (proj.repo_url ? (() => {
      try {
        const u = new URL(proj.repo_url!);
        const parts = u.pathname.replace(/^\//,'').split('/');
        if (parts.length >= 2) return `${parts[0]}/${parts[1]}`;
      } catch {}
      return '';
    })() : '');
    if (!repo) return res.json({ data: { items: [], total: 0 } });

    // Try latest success first
    // DB-first: try latest findings from DB for this project+repo
    const dbTry = await listFindingsByProjectLatest({
      project_id: projectId,
      repo_short: (repo || '').split('/').pop() || '',
      limit,
      offset,
      sort: (sort as any),
      dir: (dir as any),
      search: search || undefined,
      severity: severityFilter.length ? severityFilter : undefined,
    });
    if ((dbTry.total || 0) > 0) {
      return res.json({ data: dbTry });
    }

    let resp = await getCodeqlFindings({
      scanId: targetScan.id,
      repoParam: repo,
      lang: lang || undefined,
      search: search || undefined,
      severityFilter: severityFilter.length ? severityFilter : undefined,
      limit,
      offset,
      sort,
      dir,
    });
    if ((resp.total || 0) === 0) {
      // Fallback: check recent scans in case latest success didn't include CodeQL artifacts
      const recent = await listRecentScansByProject(projectId, 10);
      for (const s of recent) {
        const attempt = await getCodeqlFindings({
          scanId: s.id,
          repoParam: repo,
          lang: lang || undefined,
          search: search || undefined,
          severityFilter: severityFilter.length ? severityFilter : undefined,
          limit,
          offset,
          sort,
          dir,
        });
        if ((attempt.total || 0) > 0) { resp = attempt; break; }
      }
    }
    res.json({ data: resp });
  } catch (err) { next(err); }
});

projectsRouter.post('/', requireRole('project_admin'), async (req, res, next) => {
  try {
    const parsed = createProjectSchema.parse(req.body);
    const created = await createProject({
      ...parsed,
      created_by: req.session?.user?.id || null,
    });
    res.status(201).json({ data: created });
  } catch (err: any) {
    if (err?.name === 'ZodError') return res.status(422).json({ error: { code: 'validation_failed', issues: err.issues } });
    next(err);
  }
});
