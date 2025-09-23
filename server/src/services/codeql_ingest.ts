import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { logger } from '../config/logging.js';
import { config } from '../config/env.js';
import type { Scan } from '../db/repositories/scans.js';
import { bulkInsertFindings, type CodeqlFinding } from '../db/repositories/codeql_findings.js';
import { bulkUpsertScanRepos, type CodeqlScanRepo } from '../db/repositories/codeql_scan_repos.js';

function resolveRunDir(scanId: string): string | null {
  let runDir = path.resolve(config.auditWorkspaceDir, scanId);
  if (fs.existsSync(runDir)) return runDir;
  const alt = path.resolve('/workspace/runs', scanId);
  if (fs.existsSync(alt)) return alt;
  return null;
}

function listRepoDirs(runDir: string): string[] {
  try {
    return fs.readdirSync(runDir, { withFileTypes: true })
      .filter(d => d.isDirectory() && d.name !== 'markdown')
      .map(d => d.name);
  } catch {
    return [];
  }
}

function parseSarifFindings(repoDir: string, repoShort: string): Array<{
  rule_id: string;
  rule_name?: string;
  severity: string;
  file: string;
  line: number;
  message: string;
  help_uri?: string;
  language?: string;
}> {
  // Find any SARIF file first; prioritize specific languages if multiple
  const files = fs.readdirSync(repoDir).filter(f => f.startsWith(`${repoShort}_codeql_`) && f.endsWith('.sarif'));
  const out: Array<any> = [];
  for (const f of files) {
    const full = path.join(repoDir, f);
    try {
      const raw = fs.readFileSync(full, 'utf-8');
      const doc = JSON.parse(raw);
      const langSuffix = f.replace(`${repoShort}_codeql_`, '').replace('.sarif','');
      const runs = (doc?.runs || []) as any[];
      const rules: Record<string, any> = {};
      for (const run of runs) {
        for (const r of (run?.tool?.driver?.rules || [])) { if (r?.id) rules[r.id] = r; }
        for (const res of (run?.results || [])) {
          const rid = (res.ruleId || res.rule?.id || (typeof res.ruleIndex === 'number' ? (run?.tool?.driver?.rules || [])[res.ruleIndex]?.id : undefined) || '').toString();
          const loc = (res.locations && res.locations[0]) || {};
          const file = loc.physicalLocation?.artifactLocation?.uri || '';
          const line = loc.physicalLocation?.region?.startLine || 0;
          const msg = res.message?.text || '';
          const ruleMeta = (rid && rules[rid]) || undefined;
          const helpUri = ruleMeta?.helpUri || undefined;
          const secStr = (res.properties && (res.properties['security-severity'] || res.properties['security_severity'])) ||
                         (ruleMeta?.properties && (ruleMeta.properties['security-severity'] || ruleMeta.properties['security_severity'])) || null;
          const secNum = (typeof secStr === 'string') ? parseFloat(secStr) : (typeof secStr === 'number' ? secStr : null);
          let severity = 'info';
          if (secNum != null && !Number.isNaN(secNum)) {
            severity = secNum >= 9 ? 'critical' : secNum >= 7 ? 'high' : secNum >= 4 ? 'medium' : secNum > 0 ? 'low' : 'info';
          } else {
            const level = (res.level || '').toLowerCase();
            severity = level === 'error' ? 'high' : level === 'warning' ? 'medium' : level === 'note' ? 'low' : 'info';
          }
          out.push({ rule_id: rid, rule_name: ruleMeta?.shortDescription?.text, severity, file, line, message: msg, help_uri: helpUri, language: langSuffix });
        }
      }
    } catch (e) {
      // ignore malformed sarif
    }
  }
  return out;
}

function parseMarkdownTopFindings(mdPath: string): Array<{
  rule_id: string;
  severity: string;
  file: string;
  line: number;
  message: string;
}> {
  try {
    const raw = fs.readFileSync(mdPath, 'utf-8');
    const lines = raw.split(/\r?\n/);
    const startIdx = lines.findIndex(l => l.trim().toLowerCase().startsWith('## top findings'));
    if (startIdx < 0) return [];
    const tableStart = lines.findIndex((l, i) => i > startIdx && l.includes('| Severity |'));
    const sepRow = lines.findIndex((l, i) => i > tableStart && /^\|[-\s|]+\|$/.test(l.trim()));
    if (tableStart < 0 || sepRow < 0) return [];
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
    return [];
  }
}

export async function ingestCodeqlFindings(scan: Scan): Promise<{ inserted: number; repos: number }> {
  const runDir = resolveRunDir(scan.id);
  if (!runDir) {
    logger.warn({ scanId: scan.id }, 'No run directory found for ingestion');
    return { inserted: 0, repos: 0 };
  }
  const repos = listRepoDirs(runDir);
  let total = 0;
  let reposWithFindings = 0;
  const repoRows: CodeqlScanRepo[] = [];
  for (const repoShort of repos) {
    const repoDir = path.join(runDir, repoShort);
    let findings = parseSarifFindings(repoDir, repoShort);
    // Determine if SARIF artifacts exist for this repo
    let hasSarif = false;
    try {
      hasSarif = (findings.length > 0) ||
        fs.readdirSync(repoDir).some(f => f.startsWith(`${repoShort}_codeql_`) && f.endsWith('.sarif'));
    } catch {}
    if (findings.length === 0) {
      const md = path.join(repoDir, `${repoShort}_codeql.md`);
      if (fs.existsSync(md)) {
        findings = parseMarkdownTopFindings(md) as any[];
      }
    }
    if (!findings.length) continue;
    reposWithFindings++;
    const rows: CodeqlFinding[] = findings.map(f => {
      const keySrc = `${(f.rule_id||'').toLowerCase()}|${(f.file||'').toLowerCase()}|${f.line||0}|${(f.message||'').toLowerCase()}|${scan.id}`;
      const unique_key = crypto.createHash('sha256').update(keySrc).digest('hex');
      return {
        project_id: scan.project_id,
        scan_id: scan.id,
        repo_short: repoShort,
        language: (f as any).language || null,
        rule_id: f.rule_id || '',
        rule_name: (f as any).rule_name || null,
        severity: f.severity || 'unknown',
        file: f.file || '',
        line: f.line || 0,
        message: f.message || '',
        help_uri: (f as any).help_uri || null,
        unique_key,
      };
    });
    const inserted = await bulkInsertFindings(rows);
    total += inserted;

    // Aggregate counts by language for summary table and stage upsert rows
    const countsByLang = new Map<string | null, number>();
    for (const f of findings as any[]) {
      const lang: string | null = (f.language as string | undefined) || null;
      countsByLang.set(lang, (countsByLang.get(lang) || 0) + 1);
    }
    for (const [language, cnt] of countsByLang.entries()) {
      repoRows.push({
        project_id: scan.project_id,
        scan_id: scan.id,
        repo_short: repoShort,
        language,
        has_sarif: hasSarif,
        findings_count: cnt,
      });
    }
  }
  logger.info({ scanId: scan.id, total, repos: reposWithFindings }, 'CodeQL ingestion completed');
  // Best-effort upsert of per-repo summary rows
  try {
    if (repoRows.length) await bulkUpsertScanRepos(repoRows);
  } catch (e) {
    logger.warn({ e, scanId: scan.id }, 'Failed to upsert codeql_scan_repos');
  }
  return { inserted: total, repos: reposWithFindings };
}
