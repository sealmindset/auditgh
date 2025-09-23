import { Router } from 'express';
import fs from 'fs';
import path from 'path';
import { requireAuth } from '../../auth/middleware.js';
import { config } from '../../config/env.js';
import { listFindingsByScanRepo } from '../../db/repositories/codeql_findings.js';
import { pool } from '../../db/pool.js';

// Types for SARIF minimal parsing
interface SarifLocation {
  physicalLocation?: {
    artifactLocation?: { uri?: string };
    region?: { startLine?: number };
  };
}
interface SarifResult {
  ruleId?: string;
  level?: string;
  message?: { text?: string };
  locations?: SarifLocation[];
  properties?: Record<string, any>;
  rule?: { id?: string };
  ruleIndex?: number;
}
interface SarifRule {
  id?: string;
  shortDescription?: { text?: string };
  helpUri?: string;
  properties?: Record<string, any>;
}
interface SarifRun {
  tool?: { driver?: { rules?: SarifRule[] } };
  results?: SarifResult[];
}
interface SarifDoc {
  runs?: SarifRun[];
}

function severityFromSecurityScore(score: number | null | undefined): string {
  if (typeof score !== 'number') return 'unknown';
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

function severityFromLevel(level?: string): string {
  switch ((level || '').toLowerCase()) {
    case 'error': return 'high';
    case 'warning': return 'medium';
    case 'note': return 'low';
    default: return 'info';
  }
}

const SEV_RANK: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  unknown: 0,
};

function toShortRepo(repoParam: string): string {
  const p = repoParam.trim();
  if (!p) return p;
  const idx = p.lastIndexOf('/');
  return idx >= 0 ? p.slice(idx + 1) : p;
}

function safeReadJson(filePath: string): any | null {
  try {
    const raw = fs.readFileSync(filePath, 'utf-8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function listSarifFiles(repoDir: string, repoShort: string, lang?: string): string[] {
  try {
    const files = fs.readdirSync(repoDir);
    const sarifs = files
      .filter(f => f.endsWith('.sarif') && f.startsWith(`${repoShort}_codeql_`))
      .map(f => path.join(repoDir, f));
    if (lang) {
      const suffix = `_${lang}.sarif`;
      const exact = sarifs.filter(p => p.endsWith(suffix));
      if (exact.length > 0) return exact;
    }
    return sarifs;
  } catch {
    return [];
  }
}

function parseSarif(filePath: string) {
  const doc = safeReadJson(filePath) as SarifDoc | null;
  if (!doc || !doc.runs || !doc.runs.length) return [] as any[];
  const out: any[] = [];
  for (const run of doc.runs || []) {
    const rules = (run.tool?.driver?.rules || []) as SarifRule[];
    const ruleMap: Record<string, SarifRule> = {};
    for (const r of rules) if (r.id) ruleMap[r.id] = r;

    for (const res of run.results || []) {
      const rid = (res.ruleId || res.rule?.id || (typeof res.ruleIndex === 'number' ? rules[res.ruleIndex]?.id : undefined) || '').toString();
      const loc = (res.locations && res.locations[0]) || {};
      const file = loc.physicalLocation?.artifactLocation?.uri || '';
      const line = loc.physicalLocation?.region?.startLine || 0;
      const msg = res.message?.text || '';
      const ruleMeta = (rid && ruleMap[rid]) || undefined;
      const helpUri = ruleMeta?.helpUri || undefined;
      const secStr = (res.properties && (res.properties['security-severity'] || res.properties['security_severity'])) ||
                     (ruleMeta?.properties && (ruleMeta.properties['security-severity'] || ruleMeta.properties['security_severity'])) || null;
      const secNum = (typeof secStr === 'string') ? parseFloat(secStr) : (typeof secStr === 'number' ? secStr : null);
      const severity = secNum != null && !Number.isNaN(secNum) ? severityFromSecurityScore(secNum) : severityFromLevel(res.level);
      out.push({
        severity,
        rule_id: rid,
        rule_name: ruleMeta?.shortDescription?.text || undefined,
        file,
        line,
        message: msg,
        help_uri: helpUri,
      });
    }
  }
  return out;
}

function parseMarkdownTopFindings(mdPath: string) {
  try {
    const raw = fs.readFileSync(mdPath, 'utf-8');
    const lines = raw.split(/\r?\n/);
    const startIdx = lines.findIndex(l => l.trim().toLowerCase().startsWith('## top findings'));
    if (startIdx < 0) return [] as any[];
    const tableStart = lines.findIndex((l, i) => i > startIdx && l.includes('| Severity |'));
    const sepRow = lines.findIndex((l, i) => i > tableStart && /^\|[-\s|]+\|$/.test(l.trim()));
    if (tableStart < 0 || sepRow < 0) return [] as any[];
    const items: any[] = [];
    for (let i = sepRow + 1; i < lines.length; i++) {
      const row = lines[i].trim();
      if (!row.startsWith('|')) break;
      const cols = row.split('|').map(s => s.trim());
      if (cols.length < 7) continue;
      const severity = (cols[1] || '').toLowerCase() || 'unknown';
      const rule_id = cols[2] || '';
      const file = cols[3] || '';
      const line = parseInt(cols[4] || '0', 10) || 0;
      const message = cols[5] || '';
      items.push({ severity, rule_id, file, line, message });
    }
    return items;
  } catch {
    return [] as any[];
  }
}

export const codeqlRouter = Router({ mergeParams: true });

codeqlRouter.get('/findings', requireAuth, async (req, res) => {
  try {
    const scanId = (req.params as any).id as string;
    const repoParam = (req.query.repo as string) || '';
    const lang = (req.query.lang as string) || '';
    const search = ((req.query.search as string) || '').toLowerCase();
    const sevQ = (req.query.severity as string) || '';
    const sevFilter = sevQ ? sevQ.split(',').map(s => s.trim().toLowerCase()).filter(Boolean) : [];
    const limit = Math.min(parseInt((req.query.limit as string) || '50', 10) || 50, 200);
    const offset = parseInt((req.query.offset as string) || '0', 10) || 0;
    const sort = ((req.query.sort as string) || 'severity').toLowerCase();
    const dir = ((req.query.dir as string) || 'desc').toLowerCase() === 'asc' ? 'asc' : 'desc';

    if (!scanId) return res.status(400).json({ error: { code: 'bad_request', message: 'scan id required' } });
    if (!repoParam) return res.status(400).json({ error: { code: 'bad_request', message: 'repo query required' } });

    const repoShort = toShortRepo(repoParam);

    // Try DB first
    const dbSev = sevFilter.length ? sevFilter : undefined;
    const dbResp = await listFindingsByScanRepo({
      scan_id: scanId,
      repo_short: repoShort,
      limit,
      offset,
      sort: (sort as any),
      dir: (dir as any),
      search: search || undefined,
      severity: dbSev,
    });
    if ((dbResp.total || 0) > 0) {
      return res.json({ data: { items: dbResp.items, total: dbResp.total } });
    }
    // Resolve run directory; prefer configured workspace, fallback to server container mount
    let runDir = path.resolve(config.auditWorkspaceDir, scanId);
    if (!fs.existsSync(runDir)) {
      const alt = path.resolve('/workspace/runs', scanId);
      if (fs.existsSync(alt)) runDir = alt;
    }
    const repoDir = path.join(runDir, repoShort);
    const sarifs = listSarifFiles(repoDir, repoShort, lang || undefined);

    let items: any[] = [];
    if (sarifs.length > 0) {
      // Prefer first matching SARIF (or the one for specified lang)
      items = parseSarif(sarifs[0]);
    } else {
      // Fallback to markdown top findings table
      const mdPath = path.join(repoDir, `${repoShort}_codeql.md`);
      items = parseMarkdownTopFindings(mdPath);
    }

    // Filters
    if (sevFilter.length) {
      items = items.filter(it => sevFilter.includes((it.severity || 'unknown').toLowerCase()));
    }
    if (search) {
      items = items.filter(it => {
        const hay = `${it.rule_id || ''} ${it.message || ''} ${it.file || ''}`.toLowerCase();
        return hay.includes(search);
      });
    }

    // Sort
    items.sort((a, b) => {
      if (sort === 'rule') {
        return (a.rule_id || '').localeCompare(b.rule_id || '') * (dir === 'asc' ? 1 : -1);
      } else if (sort === 'file') {
        return (a.file || '').localeCompare(b.file || '') * (dir === 'asc' ? 1 : -1);
      } else if (sort === 'line') {
        return ((a.line || 0) - (b.line || 0)) * (dir === 'asc' ? 1 : -1);
      }
      // severity default
      const ra = SEV_RANK[(a.severity || 'unknown').toLowerCase()] ?? 0;
      const rb = SEV_RANK[(b.severity || 'unknown').toLowerCase()] ?? 0;
      return (rb - ra) * (dir === 'asc' ? -1 : 1);
    });

    const total = items.length;
    const paged = items.slice(offset, offset + limit);

    res.json({ data: { items: paged, total } });
  } catch (err) {
    res.status(500).json({ error: { code: 'internal_error', message: 'Failed to read CodeQL findings' } });
  }
});

// List detected repos for this scan (DB-first, fallback to filesystem)
codeqlRouter.get('/repos', requireAuth, async (req, res) => {
  try {
    const scanId = (req.params as any).id as string;
    if (!scanId) return res.status(400).json({ error: { code: 'bad_request', message: 'scan id required' } });
    // DB-first
    try {
      const { rows } = await pool.query<{repo_short:string}>(
        'select distinct repo_short from codeql_scan_repos where scan_id = $1 order by repo_short asc',
        [scanId]
      );
      if (rows && rows.length) {
        return res.json({ data: rows.map(r => r.repo_short) });
      }
    } catch {}
    // Fallback: scan filesystem under runs/<scanId>/
    let runDir = path.resolve(config.auditWorkspaceDir, scanId);
    if (!fs.existsSync(runDir)) {
      const alt = path.resolve('/workspace/runs', scanId);
      if (fs.existsSync(alt)) runDir = alt;
    }
    const found = new Set<string>();
    try {
      const entries = fs.readdirSync(runDir, { withFileTypes: true });
      for (const e of entries) {
        if (!e.isDirectory()) continue;
        const repoShort = e.name;
        const repoDir = path.join(runDir, repoShort);
        try {
          const files = fs.readdirSync(repoDir);
          const hasSarif = files.some(f => f.endsWith('.sarif') && f.startsWith(`${repoShort}_codeql_`));
          const hasMd = files.includes(`${repoShort}_codeql.md`);
          if (hasSarif || hasMd) found.add(repoShort);
        } catch {}
      }
    } catch {}
    res.json({ data: Array.from(found.values()).sort() });
  } catch {
    res.status(500).json({ error: { code: 'internal_error', message: 'Failed to list repos' } });
  }
});

// Per-severity totals for this scan and repo (DB-first; fallback to SARIF/MD)
codeqlRouter.get('/severity-totals', requireAuth, async (req, res) => {
  try {
    const scanId = (req.params as any).id as string;
    const repoParam = (req.query.repo as string) || '';
    if (!scanId) return res.status(400).json({ error: { code: 'bad_request', message: 'scan id required' } });
    if (!repoParam) return res.status(400).json({ error: { code: 'bad_request', message: 'repo query required' } });
    const repoShort = toShortRepo(repoParam);
    const totals: Record<string, number> = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
    // DB-first
    try {
      const { rows } = await pool.query<{severity:string; cnt:number}>(
        `select lower(severity) as severity, count(*)::int as cnt
           from codeql_findings where scan_id = $1 and repo_short = $2
           group by lower(severity)`,
        [scanId, repoShort]
      );
      for (const r of rows) {
        const key = (r.severity || 'unknown').toLowerCase();
        if (typeof totals[key] === 'number') totals[key] = r.cnt; else totals.unknown += r.cnt;
        totals.total += r.cnt;
      }
      if (totals.total > 0) return res.json({ data: totals });
    } catch {}
    // Fallback to filesystem parse
    let runDir = path.resolve(config.auditWorkspaceDir, scanId);
    if (!fs.existsSync(runDir)) {
      const alt = path.resolve('/workspace/runs', scanId);
      if (fs.existsSync(alt)) runDir = alt;
    }
    const repoDir = path.join(runDir, repoShort);
    const sarifs = listSarifFiles(repoDir, repoShort, undefined);
    let items: any[] = [];
    if (sarifs.length > 0) items = parseSarif(sarifs[0]);
    else items = parseMarkdownTopFindings(path.join(repoDir, `${repoShort}_codeql.md`));
    for (const it of items) {
      const sev = (it.severity || 'unknown').toLowerCase();
      if (typeof totals[sev] === 'number') totals[sev] += 1; else totals.unknown += 1;
      totals.total += 1;
    }
    res.json({ data: totals });
  } catch {
    res.status(500).json({ error: { code: 'internal_error', message: 'Failed to compute severity totals' } });
  }
});
