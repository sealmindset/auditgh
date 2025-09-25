import fs from 'fs';
import path from 'path';
import { config } from '../../config/env.js';

export type Finding = {
  severity: string;
  rule_id: string;
  rule_name?: string;
  file: string;
  line: number;
  message: string;
  help_uri?: string;
};

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
      .filter((f: string) => f.endsWith('.sarif') && f.startsWith(`${repoShort}_codeql_`))
      .map((f: string) => path.join(repoDir, f));
    if (lang) {
      const suffix = `_${lang}.sarif`;
      const exact = sarifs.filter((p: string) => p.endsWith(suffix));
      if (exact.length > 0) return exact;
    }
    return sarifs;
  } catch {
    return [];
  }
}

function parseSarif(filePath: string): Finding[] {
  const doc = safeReadJson(filePath);
  if (!doc || !doc.runs || !doc.runs.length) return [];
  const out: Finding[] = [];
  for (const run of (doc.runs || [])) {
    const rules = (run?.tool?.driver?.rules || []) as any[];
    const ruleMap: Record<string, any> = {};
    for (const r of rules) if (r?.id) ruleMap[r.id] = r;

    for (const res of (run.results || [])) {
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
      out.push({ severity, rule_id: rid, rule_name: ruleMeta?.shortDescription?.text || undefined, file, line, message: msg, help_uri: helpUri });
    }
  }
  return out;
}

function parseMarkdownTopFindings(mdPath: string): Finding[] {
  try {
    const raw = fs.readFileSync(mdPath, 'utf-8');
    const lines = raw.split(/\r?\n/);
    const startIdx = lines.findIndex((l: string) => l.trim().toLowerCase().startsWith('## top findings'));
    if (startIdx < 0) return [];
    const tableStart = lines.findIndex((l: string, i: number) => i > startIdx && l.includes('| Severity |'));
    const sepRow = lines.findIndex((l: string, i: number) => i > tableStart && /^\|[-\s|]+\|$/.test(l.trim()));
    if (tableStart < 0 || sepRow < 0) return [];
    const items: Finding[] = [];
    for (let i = sepRow + 1; i < lines.length; i++) {
      const row = lines[i].trim();
      if (!row.startsWith('|')) break;
      const cols = row.split('|').map((s: string) => s.trim());
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
    return [];
  }
}

function resolveRunDir(scanId: string): string {
  let runDir = path.resolve(config.auditWorkspaceDir, scanId);
  if (!fs.existsSync(runDir)) {
    const alt = path.resolve('/workspace/runs', scanId);
    if (fs.existsSync(alt)) runDir = alt;
  }
  return runDir;
}

export async function getCodeqlFindings(args: {
  scanId: string;
  repoParam: string;
  lang?: string;
  severityFilter?: string[];
  search?: string;
  limit?: number;
  offset?: number;
  sort?: 'severity'|'rule'|'file'|'line';
  dir?: 'asc'|'desc';
}): Promise<{ items: Finding[]; total: number; }> {
  const repoShort = toShortRepo(args.repoParam);
  const runDir = resolveRunDir(args.scanId);
  const repoDir = path.join(runDir, repoShort);
  const sarifs = listSarifFiles(repoDir, repoShort, args.lang || undefined);

  let items: Finding[] = [];
  if (sarifs.length > 0) {
    items = parseSarif(sarifs[0]);
  } else {
    const mdPath = path.join(repoDir, `${repoShort}_codeql.md`);
    items = parseMarkdownTopFindings(mdPath);
  }

  // Filters
  const sevFilter = (args.severityFilter || []).map(s => s.toLowerCase());
  if (sevFilter.length) {
    items = items.filter(it => sevFilter.includes((it.severity || 'unknown').toLowerCase()));
  }
  if (args.search) {
    const search = args.search.toLowerCase();
    items = items.filter(it => (`${it.rule_id || ''} ${it.message || ''} ${it.file || ''}`).toLowerCase().includes(search));
  }

  // Sort
  const sort = args.sort || 'severity';
  const dir = args.dir || 'desc';
  items.sort((a, b) => {
    if (sort === 'rule') return (a.rule_id || '').localeCompare(b.rule_id || '') * (dir === 'asc' ? 1 : -1);
    if (sort === 'file') return (a.file || '').localeCompare(b.file || '') * (dir === 'asc' ? 1 : -1);
    if (sort === 'line') return ((a.line || 0) - (b.line || 0)) * (dir === 'asc' ? 1 : -1);
    const ra = SEV_RANK[(a.severity || 'unknown').toLowerCase()] ?? 0;
    const rb = SEV_RANK[(b.severity || 'unknown').toLowerCase()] ?? 0;
    return (rb - ra) * (dir === 'asc' ? -1 : 1);
  });

  const total = items.length;
  const limit = Math.min(args.limit ?? 50, 200);
  const offset = args.offset ?? 0;
  const paged = items.slice(offset, offset + limit);
  return { items: paged, total };
}
